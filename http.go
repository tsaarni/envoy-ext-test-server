package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

// envoyHeadersToRemove asks Envoy to remove upstream request headers on allow.
const envoyHeadersToRemove = "x-envoy-auth-headers-to-remove"

func (s *authzServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	headers := make(map[string][]string, len(r.Header))
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = v
	}
	info := checkRequestInfo{
		protocol: "http", tls: r.TLS,
		request: requestRecord{HTTPVersion: r.Proto, Method: r.Method, Host: r.Host, Path: r.URL.RequestURI(), Headers: headers},
	}
	info.requestID = info.header("x-request-id")
	d := s.decisionFor(info)
	verdict := d.verdict
	var checkErr error
	defer func() { s.record(info, d, verdict, checkErr, start) }()

	var preview bytes.Buffer
	n, err := io.Copy(&preview, io.LimitReader(r.Body, bodyPreviewBytes))
	info.request.Body = bodyPreview(preview.Bytes())
	rest, restErr := io.Copy(io.Discard, r.Body)
	info.request.BodySize = n + rest
	if checkErr = err; checkErr == nil {
		checkErr = restErr
	}
	if checkErr != nil {
		verdict = verdictNone
		panic(http.ErrAbortHandler)
	}
	if checkErr = d.wait(r.Context()); checkErr != nil {
		verdict = verdictNone
		return
	}
	if d.verdict == verdictAbort {
		panic(http.ErrAbortHandler)
	}

	// An HTTP server can only send response headers; Envoy's configuration decides where
	// each one goes (allowed_upstream_headers, allowed_client_headers, ...).
	h := w.Header()
	h.Set("x-authz-server", s.name)
	h.Set("x-authz-verdict", d.verdict)
	if d.tag != "" {
		h.Set("x-authz-tag", d.tag)
	}
	for _, key := range pairControls {
		if d.applies(key, info.protocol) {
			for _, p := range d.pairs[key] {
				h.Add(p.name, p.value)
			}
		}
	}
	if names := d.names["upstream-remove"]; len(names) > 0 && d.applies("upstream-remove", info.protocol) {
		h.Set(envoyHeadersToRemove, strings.Join(names, ", "))
	}
	if d.verdict == verdictAllow {
		w.WriteHeader(http.StatusOK)
		return
	}
	body := s.recordBody(info, d)
	if d.body != nil {
		body = *d.body
		if h.Get("content-type") == "" {
			h["Content-Type"] = nil // no content sniffing
		}
	} else if h.Get("content-type") == "" {
		h.Set("content-type", "application/json")
	}
	w.WriteHeader(d.statusFor(info.protocol))
	_, checkErr = io.WriteString(w, body)
}
