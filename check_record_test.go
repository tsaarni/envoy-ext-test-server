package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func parseRecord(t *testing.T, body string) checkRecord {
	t.Helper()
	var r checkRecord
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("body is not a check record: %v\n%s", err, body)
	}
	return r
}

// captureLog sends the log to a buffer for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log
	log = slog.New(slog.NewJSONHandler(&buf, nil))
	t.Cleanup(func() { log = old })
	return &buf
}

func TestHTTPDenyShowsReceivedRequest(t *testing.T) {
	ts := httptest.NewServer(newTestServer())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/check?x=1", strings.NewReader("hello body"))
	req.Header.Set("x-authz", "status=403 tag=t1")
	req.Header.Add("x-dup", "one")
	req.Header.Add("x-dup", "two")
	req.Header.Set("x-json", `{"team":"a","x-role":"admin"}`)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r checkRecord
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	q := r.Request
	if q.Method != "POST" || q.Path != "/check?x=1" || q.HTTPVersion != "HTTP/1.1" || r.Tag != "t1" ||
		q.BodySize != 10 || q.Body != "hello body" || r.Attributes != nil {
		t.Fatalf("record %+v", r)
	}
	if !reflect.DeepEqual(q.Headers["x-dup"], []string{"one", "two"}) {
		t.Fatalf("x-dup %q", q.Headers["x-dup"])
	}
	if got := q.Headers["x-json"]; len(got) != 1 || got[0] != `{"team":"a","x-role":"admin"}` {
		t.Fatalf("context header %q", got)
	}
	if c := r.Controls["status"]; !reflect.DeepEqual(c, controlRecord{[]string{"403"}, "header"}) {
		t.Fatalf("controls %+v", r.Controls)
	}
}

func TestBodyPreviewIsLimited(t *testing.T) {
	ts := httptest.NewServer(newTestServer())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(strings.Repeat("a", 3000)))
	req.Header.Set("x-authz", "status=403")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r checkRecord
	_ = json.NewDecoder(resp.Body).Decode(&r)
	if r.Request.BodySize != 3000 || len(r.Request.Body) != bodyPreviewBytes {
		t.Fatalf("body_size %d preview %d", r.Request.BodySize, len(r.Request.Body))
	}
}

func TestGRPCRecordsAttributes(t *testing.T) {
	client := authv3.NewAuthorizationClient(startGRPC(t, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	routeMD, _ := structpb.NewStruct(map[string]any{"team": "a"})
	addr := func(ip string, port uint32) *corev3.Address {
		return &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address: ip, PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port}}}}
	}
	req := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source:               &authv3.AttributeContext_Peer{Address: addr("10.0.0.1", 5555), Principal: "spiffe://client", Certificate: "-----BEGIN%20CERT"},
		Destination:          &authv3.AttributeContext_Peer{Address: addr("10.0.0.2", 443)},
		TlsSession:           &authv3.AttributeContext_TLSSession{Sni: "echo.example.com"},
		RouteMetadataContext: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{"ns": routeMD}},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "GET", Scheme: "https", Host: "example.com", Path: "/", Protocol: "HTTP/2",
			HeaderMap: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: "x-authz", RawValue: []byte("status=403")},
				{Key: "x-dup", RawValue: []byte("one")},
				{Key: "x-dup", RawValue: []byte("two")},
			}},
		}},
	}}
	resp, err := client.Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDeniedResponse().GetStatus().GetCode() != 403 {
		t.Fatalf("x-authz from header_map not used: %v", resp)
	}
	r := parseRecord(t, resp.GetDeniedResponse().GetBody())
	if r.Request.HeadersField != "header_map" || !reflect.DeepEqual(r.Request.Headers["x-dup"], []string{"one", "two"}) {
		t.Fatalf("request %+v", r.Request)
	}
	a := r.Attributes
	if r.Request.Scheme != "https" || r.Request.HTTPVersion != "HTTP/2" ||
		*a.Source != (peerRecord{"10.0.0.1:5555", "spiffe://client", "-----BEGIN%20CERT"}) ||
		*a.Destination != (peerRecord{Address: "10.0.0.2:443"}) || a.TLSSNI != "echo.example.com" {
		t.Fatalf("record %+v attributes %+v", r, a)
	}
	var md bytes.Buffer
	_ = json.Compact(&md, a.RouteMetadataContext)
	if md.String() != `{"filterMetadata":{"ns":{"team":"a"}}}` || a.MetadataContext != nil {
		t.Fatalf("metadata %s / %s", a.RouteMetadataContext, a.MetadataContext)
	}
}

func TestCheckLogLine(t *testing.T) {
	buf := captureLog(t)
	ts := httptest.NewServer(newTestServer())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("authorization", "x-authz tag=t9")
	req.Header.Set("x-request-id", "rid")
	req.Header.Set("x-json", `{"team":"a"}`)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ts.Close() // waits for the handler, and its log line

	line := strings.TrimSpace(buf.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("expected one line, got:\n%s", line)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, line)
	}
	if m["msg"] != "CHECK" || m["tag"] != "t9" || m["request_id"] != "rid" || m["verdict"] != "allow" {
		t.Fatalf("log %v", m)
	}
	// Fixed order: tag and request_id right after msg, request headers last.
	iMsg, iTag, iRID, iHdr := strings.Index(line, `"msg":`), strings.Index(line, `"tag":`),
		strings.Index(line, `"request_id":`), strings.Index(line, `"headers":`)
	if !(iMsg < iTag && iTag < iRID && iRID < iHdr) || !strings.HasSuffix(line, "}}}") {
		t.Fatalf("field order: %s", line)
	}
	// The grep pattern from the README matches, with the value escaped once.
	if !strings.Contains(line, `"x-json":["{\"team\":\"a\"}"]`) {
		t.Fatalf("header not greppable: %s", line)
	}
}
