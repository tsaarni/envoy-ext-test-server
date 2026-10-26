package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var testScenarios = map[string]string{
	"redirect": "status=302 client-set=location:/login",
	"slow":     "delay=1s tag=slow",
}

func newTestServer() *authzServer {
	return &authzServer{name: "test", scenarios: testScenarios}
}

// infoWith builds a check with the given request headers (lowercase name, value pairs).
func infoWith(protocol, path string, kv ...string) checkRequestInfo {
	h := map[string][]string{}
	for i := 0; i < len(kv); i += 2 {
		h[kv[i]] = append(h[kv[i]], kv[i+1])
	}
	return checkRequestInfo{protocol: protocol, request: requestRecord{Path: path, Headers: h}}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name    string
		kv      []string
		verdict string
		status  int
		delay   time.Duration
		tag     string
		invalid string
	}{
		{name: "no controls allow", verdict: "allow", status: 200},
		{name: "status denies", kv: []string{"x-authz", "status=401"}, verdict: "deny", status: 401},
		{name: "deny defaults to 403", kv: []string{"x-authz", "verdict=deny"}, verdict: "deny", status: 403},
		{name: "error defaults to 503", kv: []string{"x-authz", "verdict=error"}, verdict: "error", status: 503},
		{name: "abort", kv: []string{"x-authz", "verdict=abort"}, verdict: "abort"},
		{name: "delay and tag", kv: []string{"x-authz", "delay=2s,tag=t1"}, verdict: "allow", status: 200, delay: 2 * time.Second, tag: "t1"},
		{name: "authorization", kv: []string{"authorization", "X-Authz status=403 delay=1s"}, verdict: "deny", status: 403, delay: time.Second},
		{name: "other schemes ignored", kv: []string{"authorization", "Bearer status=403"}, verdict: "allow", status: 200},
		{name: "allow with 403", kv: []string{"x-authz", "verdict=allow status=403"}, verdict: "deny", status: 400, invalid: "verdict allow requires 200"},
		{name: "deny with 200", kv: []string{"x-authz", "verdict=deny status=200"}, verdict: "deny", status: 400, invalid: "verdict deny requires"},
		{name: "bad verdict", kv: []string{"x-authz", "verdict=maybe"}, verdict: "deny", status: 400, invalid: "invalid verdict"},
		{name: "bad status", kv: []string{"x-authz", "status=99"}, verdict: "deny", status: 400, invalid: "invalid status"},
		{name: "bad delay", kv: []string{"x-authz", "delay=-1s"}, verdict: "deny", status: 400, invalid: "invalid delay"},
		{name: "bad tag", kv: []string{"x-authz", "tag=a%20b"}, verdict: "deny", status: 400, invalid: "invalid tag"},
		{name: "unknown control", kv: []string{"x-authz", "stats=403"}, verdict: "deny", status: 400, invalid: `header: unknown control "stats=403"`},
		{name: "bad pair", kv: []string{"x-authz", "upstream-set=x-user"}, verdict: "deny", status: 400, invalid: "expected name:value"},
		{name: "unknown scenario", kv: []string{"x-authz", "scenario=nope"}, verdict: "deny", status: 400, invalid: `unknown scenario "nope"`},
		{name: "valid tag kept on invalid", kv: []string{"x-authz", "tag=t2 status=abc"}, verdict: "deny", status: 400, tag: "t2", invalid: "invalid status"},
	}
	s := newTestServer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := s.decisionFor(infoWith("http", "/", tt.kv...))
			if d.verdict != tt.verdict || d.status != tt.status || d.delay != tt.delay || d.tag != tt.tag ||
				(tt.invalid == "") != (d.invalid == "") || !strings.Contains(d.invalid, tt.invalid) {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestCarriersMergePerControl(t *testing.T) {
	s := &authzServer{scenarios: map[string]string{"default": "status=401 delay=1s tag=d", "redirect": testScenarios["redirect"]}}
	info := infoWith("grpc", "/a?x-authz=status=402+tag=q",
		"x-authz", "status=403", "authorization", "x-authz status=404 upstream-set=a:1 upstream-set=b:2")
	info.attributes = &attributesRecord{ContextExtensions: map[string]string{"x-authz": "scenario=redirect"}}
	d := s.decisionFor(info)
	if d.invalid != "" || d.status != 404 || d.delay != time.Second || d.tag != "q" {
		t.Fatalf("got %+v", d)
	}
	want := map[string]controlRecord{
		"status":       {[]string{"404"}, "authorization"},
		"delay":        {[]string{"1s"}, "default"},
		"tag":          {[]string{"q"}, "query"},
		"scenario":     {[]string{"redirect"}, "context"},
		"client-set":   {[]string{"location:/login"}, "scenario"},
		"upstream-set": {[]string{"a:1", "b:2"}, "authorization"},
	}
	if !reflect.DeepEqual(d.controls, want) {
		t.Fatalf("controls %+v", d.controls)
	}
}

func TestScenarioIsOverriddenByItsCarrier(t *testing.T) {
	d := newTestServer().decisionFor(infoWith("http", "/", "x-authz", "status=307 scenario=redirect"))
	if d.status != 307 || d.pairs["client-set"][0] != (header{"location", "/login"}) {
		t.Fatalf("got %+v", d)
	}
}

func TestPairs(t *testing.T) {
	d := newTestServer().decisionFor(infoWith("grpc", "/",
		"x-authz", "client-set=:path:/x upstream-set=x-a:with%20space%2Cand%20comma upstream-set=x-b: upstream-remove=x-c"))
	want := map[string][]header{"client-set": {{":path", "/x"}}, "upstream-set": {{"x-a", "with space,and comma"}, {"x-b", ""}}}
	if d.invalid != "" || !reflect.DeepEqual(d.pairs, want) || !reflect.DeepEqual(d.names["upstream-remove"], []string{"x-c"}) {
		t.Fatalf("got %+v", d)
	}
}

func TestIgnored(t *testing.T) {
	all := "upstream-set=a:1 upstream-remove=b client-set=c:1 client-add-if-absent=d:1 query-set=e:1 metadata-set=f:1 body=x"
	tests := []struct {
		protocol, controls string
		want               []string
	}{
		{"grpc", all, []string{"body"}},
		{"http", all, []string{"body", "query-set"}},
		{"grpc", "verdict=deny " + all, []string{"client-add-if-absent", "query-set", "upstream-remove", "upstream-set"}},
		{"http", "verdict=deny " + all, []string{"query-set", "upstream-remove", "upstream-set"}},
		{"http", "verdict=error status=429", []string{"status"}},
		{"grpc", "verdict=error status=429", []string{}},
		{"grpc", "verdict=abort status=500 delay=1s client-set=a:1", []string{"client-set", "status"}},
	}
	for _, tt := range tests {
		d := newTestServer().decisionFor(infoWith(tt.protocol, "/", "x-authz", tt.controls))
		if got := d.ignored(tt.protocol); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s %q: ignored %v, want %v", tt.protocol, tt.controls, got, tt.want)
		}
	}
}

func TestValidateScenarios(t *testing.T) {
	for _, bad := range []map[string]string{{"a": "status=abc"}, {"a": "scenario=b"}, {"a b": "status=403"}, {"a": "nope=1"}} {
		if validateScenarios(bad) == nil {
			t.Errorf("%v: expected error", bad)
		}
	}
	if err := validateScenarios(testScenarios); err != nil {
		t.Fatal(err)
	}
}

func doHTTP(t *testing.T, client *http.Client, url string, kv ...string) (*http.Response, string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for i := 0; i < len(kv); i += 2 {
		req.Header.Add(kv[i], kv[i+1])
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

func TestHTTP(t *testing.T) {
	ts := httptest.NewTLSServer(newTestServer())
	defer ts.Close()

	t.Run("allow", func(t *testing.T) {
		resp, _, err := doHTTP(t, ts.Client(), ts.URL+"/check")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("resp %v err %v", resp, err)
		}
		if resp.Header.Get("x-authz-server") != "test" || resp.Header.Get("x-authz-verdict") != "allow" {
			t.Fatalf("headers %v", resp.Header)
		}
	})
	t.Run("allow sends header controls as response headers", func(t *testing.T) {
		resp, _, err := doHTTP(t, ts.Client(), ts.URL, "authorization",
			"x-authz upstream-set=x-user:alice upstream-append=x-user:bob client-add=set-cookie:a=1 metadata-set=x-md:v upstream-remove=x-secret,upstream-remove=x-other")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("resp %v err %v", resp, err)
		}
		if got := resp.Header.Values("x-user"); !reflect.DeepEqual(got, []string{"alice", "bob"}) ||
			resp.Header.Get("set-cookie") != "a=1" || resp.Header.Get("x-md") != "v" ||
			resp.Header.Get(envoyHeadersToRemove) != "x-secret, x-other" {
			t.Fatalf("headers %v", resp.Header)
		}
	})
	t.Run("deny", func(t *testing.T) {
		resp, body, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "status=403")
		if err != nil || resp.StatusCode != 403 || resp.Header.Get("content-type") != "application/json" {
			t.Fatalf("resp %v body %q err %v", resp, body, err)
		}
		r := parseRecord(t, body)
		if r.Server != "test" || r.Status != 403 || r.Verdict != "deny" || r.Protocol != "http" || r.Request.HeadersField != "" {
			t.Fatalf("record %+v", r)
		}
	})
	t.Run("deny drops upstream controls", func(t *testing.T) {
		client := *ts.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, _, err := doHTTP(t, &client, ts.URL+"/?x-authz=scenario=redirect+upstream-set=x-user:alice")
		if err != nil || resp.StatusCode != 302 || resp.Header.Get("location") != "/login" || resp.Header.Get("x-user") != "" {
			t.Fatalf("resp %v err %v", resp, err)
		}
	})
	t.Run("custom body", func(t *testing.T) {
		resp, body, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "status=401 body=go%20away")
		if err != nil || resp.StatusCode != 401 || body != "go away" || resp.Header.Get("content-type") != "" {
			t.Fatalf("resp %v body %q err %v", resp, body, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		resp, body, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "status=nope")
		if err != nil || resp.StatusCode != 400 {
			t.Fatalf("resp %v err %v", resp, err)
		}
		if r := parseRecord(t, body); r.Status != 400 || !strings.Contains(r.Error, "invalid status") {
			t.Fatalf("record %+v", r)
		}
	})
	t.Run("error sends 5xx", func(t *testing.T) {
		resp, body, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "verdict=error status=429")
		if err != nil || resp.StatusCode != 503 {
			t.Fatalf("resp %v err %v", resp, err)
		}
		if r := parseRecord(t, body); r.Verdict != "error" || r.Status != 503 || !reflect.DeepEqual(r.Ignored, []string{"status"}) {
			t.Fatalf("record %+v", r)
		}
	})
	t.Run("delay", func(t *testing.T) {
		start := time.Now()
		resp, _, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "delay=200ms")
		if err != nil || resp.StatusCode != 200 || time.Since(start) < 200*time.Millisecond {
			t.Fatalf("resp %v err %v elapsed %v", resp, err, time.Since(start))
		}
	})
	t.Run("abort drops the connection", func(t *testing.T) {
		if _, _, err := doHTTP(t, ts.Client(), ts.URL, "x-authz", "verdict=abort"); err == nil {
			t.Fatal("expected connection error")
		}
	})
}

func startGRPC(t *testing.T, tlsCfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var serverOpts []grpc.ServerOption
	var dialCreds grpc.DialOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	if tlsCfg != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		pool := x509.NewCertPool()
		leaf, _ := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
		pool.AddCert(leaf)
		dialCreds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "example.com"}))
	}
	srv := grpc.NewServer(serverOpts...)
	authv3.RegisterAuthorizationServer(srv, &grpcAuthzServer{authzServer: newTestServer()})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), dialCreds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func checkRequest(kv ...string) *authv3.CheckRequest {
	h := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		h[kv[i]] = kv[i+1]
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		ContextExtensions: map[string]string{"env": "staging"},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: "GET", Host: "example.com", Path: "/check", Headers: h,
		}},
	}}
}

// headerList renders headers as "name=value append action" for comparison.
func headerList(hs []*corev3.HeaderValueOption) []string {
	var out []string
	for _, h := range hs {
		s := h.GetHeader().GetKey() + "=" + h.GetHeader().GetValue()
		if h.Append != nil {
			s += map[bool]string{true: " append", false: " set"}[h.GetAppend().GetValue()]
		} else {
			s += " " + h.GetAppendAction().String()
		}
		out = append(out, s)
	}
	return out
}

func testGRPC(t *testing.T, conn *grpc.ClientConn) {
	client := authv3.NewAuthorizationClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("allow", func(t *testing.T) {
		resp, err := client.Check(ctx, checkRequest("x-authz", "tag=t1"))
		if err != nil || resp.GetStatus().GetCode() != int32(codes.OK) {
			t.Fatalf("resp %v err %v", resp, err)
		}
		want := []string{"x-authz-server=test set", "x-authz-verdict=allow set", "x-authz-tag=t1 set"}
		if got := headerList(resp.GetOkResponse().GetHeaders()); !reflect.DeepEqual(got, want) {
			t.Fatalf("headers %v", got)
		}
	})
	t.Run("allow mutations", func(t *testing.T) {
		resp, err := client.Check(ctx, checkRequest("authorization", "x-authz "+
			"upstream-set=x-user:alice upstream-append=x-group:b upstream-remove=x-secret "+
			"client-set=c1:1 client-add=c2:2 client-add-if-absent=c3:3 client-set-if-exists=c4:4 "+
			"query-set=q:1 query-remove=x-authz metadata-set=user:alice"))
		if err != nil {
			t.Fatal(err)
		}
		ok := resp.GetOkResponse()
		if got := headerList(ok.GetHeaders())[2:]; !reflect.DeepEqual(got, []string{"x-user=alice set", "x-group=b append"}) {
			t.Fatalf("headers %v", got)
		}
		wantClient := []string{"c1=1 OVERWRITE_IF_EXISTS_OR_ADD", "c2=2 APPEND_IF_EXISTS_OR_ADD", "c3=3 ADD_IF_ABSENT", "c4=4 OVERWRITE_IF_EXISTS"}
		if got := headerList(ok.GetResponseHeadersToAdd()); !reflect.DeepEqual(got, wantClient) {
			t.Fatalf("response headers %v", got)
		}
		if !reflect.DeepEqual(ok.GetHeadersToRemove(), []string{"x-secret"}) || ok.GetQueryParametersToSet()[0].GetKey() != "q" ||
			!reflect.DeepEqual(ok.GetQueryParametersToRemove(), []string{"x-authz"}) ||
			resp.GetDynamicMetadata().GetFields()["user"].GetStringValue() != "alice" {
			t.Fatalf("ok %v", resp)
		}
	})
	t.Run("deny", func(t *testing.T) {
		resp, err := client.Check(ctx, checkRequest("x-authz", "status=401 client-set=www-authenticate:Basic client-add=set-cookie:a=1"))
		if err != nil || resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
			t.Fatalf("resp %v err %v", resp, err)
		}
		denied := resp.GetDeniedResponse()
		want := []string{"x-authz-server=test set", "x-authz-verdict=deny set", "content-type=application/json set",
			"www-authenticate=Basic set", "set-cookie=a=1 append"}
		if denied.GetStatus().GetCode() != 401 || !reflect.DeepEqual(headerList(denied.GetHeaders()), want) {
			t.Fatalf("denied %v", denied)
		}
		r := parseRecord(t, denied.GetBody())
		if r.Server != "test" || r.Status != 401 || r.Attributes.ContextExtensions["env"] != "staging" || r.Request.HeadersField != "headers" {
			t.Fatalf("record %+v", r)
		}
	})
	t.Run("invalid denies with 400", func(t *testing.T) {
		resp, err := client.Check(ctx, checkRequest("x-authz", "delay=later"))
		if err != nil || resp.GetDeniedResponse().GetStatus().GetCode() != 400 {
			t.Fatalf("resp %v err %v", resp, err)
		}
	})
	t.Run("error sends error_response", func(t *testing.T) {
		resp, err := client.Check(ctx, checkRequest("x-authz", "verdict=error status=429 body=busy client-set=retry-after:1"))
		if err != nil || resp.GetStatus().GetCode() != int32(codes.Unavailable) {
			t.Fatalf("resp %v err %v", resp, err)
		}
		e := resp.GetErrorResponse()
		if e.GetStatus().GetCode() != 429 || e.GetBody() != "busy" || headerList(e.GetHeaders())[2] != "retry-after=1 set" {
			t.Fatalf("error_response %v", e)
		}
	})
	t.Run("abort fails the RPC", func(t *testing.T) {
		_, err := client.Check(ctx, checkRequest("x-authz", "verdict=abort"))
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("context extension carrier", func(t *testing.T) {
		req := checkRequest()
		req.Attributes.ContextExtensions["x-authz"] = "scenario=redirect"
		resp, err := client.Check(ctx, req)
		if err != nil || resp.GetDeniedResponse().GetStatus().GetCode() != 302 {
			t.Fatalf("resp %v err %v", resp, err)
		}
	})
	t.Run("delay honors cancellation", func(t *testing.T) {
		short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		_, err := client.Check(short, checkRequest("x-authz", "delay=10s"))
		if status.Code(err) != codes.DeadlineExceeded {
			t.Fatalf("err %v", err)
		}
	})
}

func TestGRPCPlaintext(t *testing.T) {
	testGRPC(t, startGRPC(t, nil))
}

func TestGRPCTLS(t *testing.T) {
	// httptest ships a certificate valid for example.com.
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	testGRPC(t, startGRPC(t, &tls.Config{Certificates: ts.TLS.Certificates}))
}
