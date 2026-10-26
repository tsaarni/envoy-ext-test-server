package main

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"time"
)

// bodyPreviewBytes is how much of the request body is shown in logs and deny responses.
const bodyPreviewBytes = 1024

// checkRequestInfo describes one check: the client request as Envoy described it,
// the gRPC attributes and the Envoy-to-server connection.
type checkRequestInfo struct {
	protocol   string // grpc or http
	requestID  string // Envoy's x-request-id
	request    requestRecord
	attributes *attributesRecord    // gRPC only
	tls        *tls.ConnectionState // Envoy-to-server connection
}

// header returns the first value of a request header.
func (info checkRequestInfo) header(name string) string {
	if v := info.request.Headers[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (info checkRequestInfo) contextExtension(key string) string {
	if info.attributes == nil {
		return ""
	}
	return info.attributes.ContextExtensions[key]
}

func bodyPreview(b []byte) string {
	if len(b) > bodyPreviewBytes {
		b = b[:bodyPreviewBytes]
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// requestRecord is the client request as Envoy described it in the check.
type requestRecord struct {
	HTTPVersion  string              `json:"http_version"`
	Method       string              `json:"method"`
	Scheme       string              `json:"scheme,omitempty"` // gRPC only
	Host         string              `json:"host"`
	Path         string              `json:"path"`                    // includes the query string
	HeadersField string              `json:"headers_field,omitempty"` // gRPC only: headers (repeated joined with ,) or header_map
	BodySize     int64               `json:"body_size"`
	Body         string              `json:"body"` // first bodyPreviewBytes
	Headers      map[string][]string `json:"headers"`
}

// peerRecord is AttributeContext.Peer.
type peerRecord struct {
	Address     string `json:"address,omitempty"`
	Principal   string `json:"principal,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// attributesRecord holds the gRPC AttributeContext fields beyond the request. Envoy does not send them to HTTP servers.
type attributesRecord struct {
	Source               *peerRecord       `json:"source,omitempty"`
	Destination          *peerRecord       `json:"destination,omitempty"`
	TLSSNI               string            `json:"tls_sni,omitempty"`
	ContextExtensions    map[string]string `json:"context_extensions,omitempty"`
	MetadataContext      json.RawMessage   `json:"metadata_context,omitempty"`
	RouteMetadataContext json.RawMessage   `json:"route_metadata_context,omitempty"`
}

// connectionRecord describes the connection from Envoy to this server, not the client's connection.
type connectionRecord struct {
	TLS        bool   `json:"tls"`
	SNI        string `json:"sni"`
	ClientCert string `json:"client_cert"` // subject of Envoy's client certificate
}

// checkRecord is what the server received and sent in one check. It is the CHECK
// log line and the default deny and error body.
type checkRecord struct {
	Server          string                   `json:"server"`
	Tag             string                   `json:"tag"`
	RequestID       string                   `json:"request_id"`
	Protocol        string                   `json:"protocol"`
	Verdict         string                   `json:"verdict"`
	Status          int                      `json:"status"`
	Error           string                   `json:"error"`
	Controls        map[string]controlRecord `json:"controls"`
	Ignored         []string                 `json:"ignored"`
	EnvoyConnection connectionRecord         `json:"envoy_connection"`
	Attributes      *attributesRecord        `json:"attributes,omitempty"`
	Request         requestRecord            `json:"request"`
}

func connection(state *tls.ConnectionState) connectionRecord {
	c := connectionRecord{TLS: state != nil}
	if state != nil {
		c.SNI = state.ServerName
		if len(state.PeerCertificates) > 0 {
			c.ClientCert = state.PeerCertificates[0].Subject.String()
		}
	}
	return c
}

// newRecord describes the check; verdict is what was sent.
func (s *authzServer) newRecord(info checkRequestInfo, d decision, verdict string, err error) checkRecord {
	status := 0
	ignored := []string{}
	if verdict == verdictAllow || verdict == verdictDeny || verdict == verdictError {
		status = d.statusFor(info.protocol)
	}
	if verdict != verdictNone {
		ignored = d.ignored(info.protocol)
	}
	controls := d.controls
	if controls == nil {
		controls = map[string]controlRecord{}
	}
	request := info.request
	if request.Headers == nil {
		request.Headers = map[string][]string{}
	}
	rec := checkRecord{
		Server: s.name, Tag: d.tag, RequestID: info.requestID, Protocol: info.protocol,
		Verdict: verdict, Status: status, Error: d.invalid, Controls: controls, Ignored: ignored,
		EnvoyConnection: connection(info.tls), Attributes: info.attributes, Request: request,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	return rec
}

// recordBody is the default deny and error body: the check record.
func (s *authzServer) recordBody(info checkRequestInfo, d decision) string {
	b, _ := json.MarshalIndent(s.newRecord(info, d, d.verdict, nil), "", "  ")
	return string(b) + "\n"
}

// record publishes the result of a check to the metrics and the log.
func (s *authzServer) record(info checkRequestInfo, d decision, verdict string, err error, start time.Time) {
	r := s.newRecord(info, d, verdict, err)
	s.metrics.observe(r, time.Since(start))
	if s.quiet {
		return
	}
	// The server name is already in the "instance" attribute of the logger.
	attrs := []any{
		"tag", r.Tag, "request_id", r.RequestID, "protocol", r.Protocol, "verdict", r.Verdict, "status", r.Status,
		"error", r.Error, "controls", r.Controls, "ignored", r.Ignored, "envoy_connection", r.EnvoyConnection,
	}
	if r.Attributes != nil {
		attrs = append(attrs, "attributes", r.Attributes)
	}
	attrs = append(attrs, "request", r.Request)
	log.Info("CHECK", attrs...)
}
