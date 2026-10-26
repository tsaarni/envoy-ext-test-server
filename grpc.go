package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type grpcAuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	*authzServer
}

// headerWithAppend is a header for OkHttpResponse.headers and the deny and error
// headers, where Envoy reads only the append field.
func headerWithAppend(h header, appendValue bool) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: h.name, Value: h.value},
		Append: wrapperspb.Bool(appendValue),
	}
}

// clientAppendActions maps the client-* controls on allow to OkHttpResponse.response_headers_to_add.
var clientAppendActions = map[string]corev3.HeaderValueOption_HeaderAppendAction{
	"client-set":           corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	"client-add":           corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
	"client-add-if-absent": corev3.HeaderValueOption_ADD_IF_ABSENT,
	"client-set-if-exists": corev3.HeaderValueOption_OVERWRITE_IF_EXISTS,
}

// grpcHeaders returns the request headers with all values of repeated headers.
// Envoy keeps repeated headers apart only in header_map (encode_raw_headers);
// in headers it joins them with ",".
func grpcHeaders(request *authv3.AttributeContext_HttpRequest) (map[string][]string, string) {
	headers := map[string][]string{}
	if hm := request.GetHeaderMap(); hm != nil {
		for _, h := range hm.GetHeaders() {
			v := h.GetValue()
			if v == "" {
				v = strings.ToValidUTF8(string(h.GetRawValue()), "\uFFFD")
			}
			k := strings.ToLower(h.GetKey())
			headers[k] = append(headers[k], v)
		}
		return headers, "header_map"
	}
	for k, v := range request.GetHeaders() {
		headers[strings.ToLower(k)] = []string{v}
	}
	return headers, "headers"
}

// protoJSON returns m as JSON, or nil if m is empty.
func protoJSON(m proto.Message) json.RawMessage {
	if m == nil || !m.ProtoReflect().IsValid() || proto.Size(m) == 0 {
		return nil
	}
	b, err := protojson.Marshal(m)
	if err != nil {
		return nil
	}
	// protojson output has unstable whitespace; make it compact for grep.
	var out bytes.Buffer
	if json.Compact(&out, b) != nil {
		return nil
	}
	return out.Bytes()
}

func address(a *corev3.Address) string {
	if sa := a.GetSocketAddress(); sa != nil {
		return fmt.Sprintf("%s:%d", sa.GetAddress(), sa.GetPortValue())
	}
	return a.GetPipe().GetPath()
}

func peerOf(p *authv3.AttributeContext_Peer) *peerRecord {
	r := &peerRecord{Address: address(p.GetAddress()), Principal: p.GetPrincipal(), Certificate: p.GetCertificate()}
	if *r == (peerRecord{}) {
		return nil
	}
	return r
}

func (s *grpcAuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (resp *authv3.CheckResponse, err error) {
	start := time.Now()
	attrs := req.GetAttributes()
	request := attrs.GetRequest().GetHttp()
	reqHeaders, field := grpcHeaders(request)
	body := request.GetRawBody()
	if len(body) == 0 {
		body = []byte(request.GetBody())
	}
	info := checkRequestInfo{
		protocol: "grpc", requestID: request.GetId(),
		request: requestRecord{
			HTTPVersion: request.GetProtocol(), Method: request.GetMethod(), Scheme: request.GetScheme(),
			Host: request.GetHost(), Path: request.GetPath(), HeadersField: field, Headers: reqHeaders,
			BodySize: int64(len(body)), Body: bodyPreview(body),
		},
		attributes: &attributesRecord{
			Source: peerOf(attrs.GetSource()), Destination: peerOf(attrs.GetDestination()),
			TLSSNI: attrs.GetTlsSession().GetSni(), ContextExtensions: attrs.GetContextExtensions(),
			MetadataContext: protoJSON(attrs.GetMetadataContext()), RouteMetadataContext: protoJSON(attrs.GetRouteMetadataContext()),
		},
	}
	if info.requestID == "" {
		info.requestID = info.header("x-request-id")
	}
	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			info.tls = &tlsInfo.State
		}
	}
	d := s.decisionFor(info)
	verdict := d.verdict
	defer func() { s.record(info, d, verdict, err, start) }()
	if err = d.wait(ctx); err != nil {
		verdict = verdictNone
		return nil, status.FromContextError(err).Err()
	}

	own := []header{{"x-authz-server", s.name}, {"x-authz-verdict", d.verdict}}
	if d.tag != "" {
		own = append(own, header{"x-authz-tag", d.tag})
	}
	switch d.verdict {
	case verdictAbort:
		return nil, status.Errorf(codes.Unavailable, "abort requested from %s", s.name)
	case verdictAllow:
		return &authv3.CheckResponse{
			Status:          &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse:    &authv3.CheckResponse_OkResponse{OkResponse: s.okResponse(d, own)},
			DynamicMetadata: dynamicMetadata(d),
		}, nil
	}
	if d.body == nil {
		own = append(own, header{"content-type", "application/json"})
	}
	reply := &authv3.DeniedHttpResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode(d.status)}}
	for _, h := range own {
		reply.Headers = append(reply.Headers, headerWithAppend(h, false))
	}
	for _, key := range []string{"client-set", "client-add"} {
		for _, h := range d.pairs[key] {
			reply.Headers = append(reply.Headers, headerWithAppend(h, key == "client-add"))
		}
	}
	if d.body != nil {
		reply.Body = *d.body
	} else {
		reply.Body = s.recordBody(info, d)
	}
	resp = &authv3.CheckResponse{DynamicMetadata: dynamicMetadata(d)}
	if d.verdict == verdictError {
		resp.Status = &rpcstatus.Status{Code: int32(codes.Unavailable)}
		resp.HttpResponse = &authv3.CheckResponse_ErrorResponse{ErrorResponse: reply}
	} else {
		resp.Status = &rpcstatus.Status{Code: int32(codes.PermissionDenied)}
		resp.HttpResponse = &authv3.CheckResponse_DeniedResponse{DeniedResponse: reply}
	}
	return resp, nil
}

func (s *grpcAuthzServer) okResponse(d decision, own []header) *authv3.OkHttpResponse {
	ok := &authv3.OkHttpResponse{
		HeadersToRemove:         d.names["upstream-remove"],
		QueryParametersToRemove: d.names["query-remove"],
	}
	for _, h := range own {
		ok.Headers = append(ok.Headers, headerWithAppend(h, false))
	}
	for _, key := range upstreamHeaderControls {
		for _, h := range d.pairs[key] {
			ok.Headers = append(ok.Headers, headerWithAppend(h, key == "upstream-append"))
		}
	}
	for _, key := range clientHeaderControls {
		for _, h := range d.pairs[key] {
			ok.ResponseHeadersToAdd = append(ok.ResponseHeadersToAdd, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{Key: h.name, Value: h.value}, AppendAction: clientAppendActions[key],
			})
		}
	}
	for _, q := range d.pairs["query-set"] {
		ok.QueryParametersToSet = append(ok.QueryParametersToSet, &corev3.QueryParameter{Key: q.name, Value: q.value})
	}
	return ok
}

// dynamicMetadata returns the metadata-set controls as CheckResponse.dynamic_metadata.
func dynamicMetadata(d decision) *structpb.Struct {
	pairs := d.pairs["metadata-set"]
	if len(pairs) == 0 {
		return nil
	}
	m := &structpb.Struct{Fields: map[string]*structpb.Value{}}
	for _, p := range pairs {
		m.Fields[p.name] = structpb.NewStringValue(p.value)
	}
	return m
}
