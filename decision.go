package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Verdicts. Requested verdicts are allow, deny, error and abort; none is recorded
// when nothing was sent (client went away, body read failed).
const (
	verdictAllow = "allow"
	verdictDeny  = "deny"
	verdictError = "error"
	verdictAbort = "abort"
	verdictNone  = "none"
)

// Carriers, in the order they are merged: later carriers override earlier ones per control.
const (
	carrierDefault       = "default"
	carrierScenario      = "scenario"
	carrierContext       = "context"
	carrierQuery         = "query"
	carrierHeader        = "header"
	carrierAuthorization = "authorization"
)

// controlName is the context extension, query parameter and header that carry controls,
// and the Authorization scheme.
const controlName = "x-authz"

// singleControls take one value; the last one wins.
var singleControls = []string{"verdict", "status", "delay", "body", "tag", "scenario"}

// Header controls take name:value; the name ends at the first ':' after the first character,
// so pseudo headers (:path:/x) work. Remove controls take a name.
var (
	upstreamHeaderControls = []string{"upstream-set", "upstream-append"}
	clientHeaderControls   = []string{"client-set", "client-add", "client-add-if-absent", "client-set-if-exists"}
	pairControls           = append(append(slices.Clone(upstreamHeaderControls), clientHeaderControls...), "query-set", "metadata-set")
	nameControls           = []string{"upstream-remove", "query-remove"}
)

func knownControl(key string) bool {
	return slices.Contains(singleControls, key) || slices.Contains(pairControls, key) || slices.Contains(nameControls, key)
}

func listControl(key string) bool { return !slices.Contains(singleControls, key) }

// control is one key=value as sent by the client, value percent-decoded.
type control struct{ key, value string }

// controlRecord is the merged value of one control and the carrier it came from.
type controlRecord struct {
	Values  []string `json:"values"`
	Carrier string   `json:"carrier"`
}

// carrier is the raw control text from one place in the check.
type carrier struct{ name, text string }

// parseControls parses `key=value key=value`, separated by spaces or commas.
func parseControls(text string) ([]control, error) {
	var controls []control
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == ',' }) {
		k, v, ok := strings.Cut(field, "=")
		if !ok || !knownControl(k) {
			return nil, fmt.Errorf("unknown control %q", field)
		}
		v, err := url.PathUnescape(v)
		if err != nil {
			return nil, fmt.Errorf("control %q: invalid percent-encoding", field)
		}
		controls = append(controls, control{k, v})
	}
	return controls, nil
}

// authorizationControls returns the controls of `Authorization: x-authz ...`, or "" for other schemes.
func authorizationControls(value string) string {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(value), " ")
	if !strings.EqualFold(scheme, controlName) {
		return ""
	}
	return rest
}

// queryControls returns the x-authz query parameters of path.
func queryControls(path string) string {
	_, query, ok := strings.Cut(path, "?")
	if !ok {
		return ""
	}
	values, _ := url.ParseQuery(query) // keeps the parameters that parse
	return strings.Join(values[controlName], " ")
}

// mergeControls merges the carriers in order. A scenario=name control expands the scenario
// first, so the other controls of the same carrier override it.
func mergeControls(carriers []carrier, scenarios map[string]string) (map[string]controlRecord, error) {
	merged := map[string]controlRecord{}
	apply := func(controls []control, carrierName string) {
		own := map[string]controlRecord{}
		for _, c := range controls {
			r := own[c.key]
			r.Carrier = carrierName
			if listControl(c.key) {
				r.Values = append(r.Values, c.value)
			} else {
				r.Values = []string{c.value}
			}
			own[c.key] = r
		}
		for k, r := range own {
			merged[k] = r
		}
	}
	for _, c := range carriers {
		controls, err := parseControls(c.text)
		if err != nil {
			return merged, fmt.Errorf("%s: %w", c.name, err)
		}
		for _, ctl := range controls {
			if ctl.key != "scenario" {
				continue
			}
			text, ok := scenarios[ctl.value]
			if !ok {
				return merged, fmt.Errorf("%s: unknown scenario %q", c.name, ctl.value)
			}
			scenario, _ := parseControls(text) // validated at startup
			apply(scenario, carrierScenario)
		}
		apply(controls, c.name)
	}
	return merged, nil
}

type header struct{ name, value string }

// decision is the reply the controls ask for.
type decision struct {
	verdict  string
	status   int // HTTP status for allow, deny and error; 0 for abort
	delay    time.Duration
	body     *string             // deny and error body; nil sends the check record
	tag      string              // echoed in logs, metrics and responses
	pairs    map[string][]header // name:value controls by key
	names    map[string][]string // name controls by key
	controls map[string]controlRecord
	invalid  string // why the controls were rejected, empty if valid
}

func (d decision) has(key string) bool { _, ok := d.controls[key]; return ok }

func (d decision) value(key string) string {
	if r, ok := d.controls[key]; ok {
		return r.Values[len(r.Values)-1]
	}
	return ""
}

func validTag(tag string) bool {
	if len(tag) > 128 {
		return false
	}
	return strings.IndexFunc(tag, func(r rune) bool { return r <= ' ' || r > '~' }) < 0
}

func validStatus(status int) bool {
	return status >= 200 && status <= 599
}

func splitPair(v string) (header, bool) {
	if len(v) < 2 {
		return header{}, false
	}
	i := strings.IndexByte(v[1:], ':')
	if i < 0 {
		return header{}, false
	}
	return header{v[:i+1], v[i+2:]}, true
}

// decide turns merged controls into a decision.
func decide(controls map[string]controlRecord) (decision, error) {
	d := decision{controls: controls, pairs: map[string][]header{}, names: map[string][]string{}}
	if d.tag = d.value("tag"); !validTag(d.tag) {
		d.tag = ""
		return d, fmt.Errorf("invalid tag %q: expected up to 128 printable characters without spaces", d.value("tag"))
	}
	if d.has("status") {
		n, err := strconv.Atoi(d.value("status"))
		if err != nil || !validStatus(n) {
			return d, fmt.Errorf("invalid status %q: expected 200..599", d.value("status"))
		}
		d.status = n
	}
	switch d.verdict = d.value("verdict"); d.verdict {
	case "":
		d.verdict = verdictAllow
		if d.status != 0 && d.status != http.StatusOK {
			d.verdict = verdictDeny
		}
	case verdictAllow:
		if d.status != 0 && d.status != http.StatusOK {
			return d, fmt.Errorf("invalid status %d: verdict allow requires 200", d.status)
		}
	case verdictDeny:
		if d.status == http.StatusOK {
			return d, errors.New("invalid status 200: verdict deny requires another status")
		}
	case verdictError, verdictAbort:
	default:
		return d, fmt.Errorf("invalid verdict %q: expected allow, deny, error or abort", d.verdict)
	}
	if d.status == 0 {
		d.status = map[string]int{verdictAllow: 200, verdictDeny: 403, verdictError: 503}[d.verdict]
	}
	if d.has("delay") {
		var err error
		if d.delay, err = time.ParseDuration(d.value("delay")); err != nil || d.delay < 0 {
			return d, fmt.Errorf("invalid delay %q: expected a nonnegative Go duration", d.value("delay"))
		}
	}
	if d.has("body") {
		body := d.value("body")
		d.body = &body
	}
	for _, key := range pairControls {
		for _, v := range d.controls[key].Values {
			h, ok := splitPair(v)
			if !ok {
				return d, fmt.Errorf("invalid %s %q: expected name:value", key, v)
			}
			d.pairs[key] = append(d.pairs[key], h)
		}
	}
	for _, key := range nameControls {
		for _, v := range d.controls[key].Values {
			if v == "" {
				return d, fmt.Errorf("invalid %s: expected a name", key)
			}
			d.names[key] = append(d.names[key], v)
		}
	}
	return d, nil
}

// invalidDecision denies with 400 and explains why.
func invalidDecision(controls map[string]controlRecord, tag string, err error) decision {
	return decision{verdict: verdictDeny, status: http.StatusBadRequest, tag: tag, controls: controls, invalid: err.Error()}
}

// statusFor is the status sent over protocol. An HTTP server can only signal an
// error with 5xx, so other statuses are replaced with 503 (and listed as ignored).
func (d decision) statusFor(protocol string) int {
	if d.verdict == verdictError && protocol == "http" && d.status < 500 {
		return http.StatusServiceUnavailable
	}
	return d.status
}

// applies tells if a control has a place in the reply for this protocol and verdict.
func (d decision) applies(key, protocol string) bool {
	grpc := protocol == "grpc"
	switch {
	case key == "verdict" || key == "delay" || key == "tag" || key == "scenario":
		return true
	case d.verdict == verdictAbort:
		return false
	case key == "status":
		return d.statusFor(protocol) == d.status
	case key == "body":
		return d.verdict != verdictAllow
	case strings.HasPrefix(key, "upstream-"):
		return d.verdict == verdictAllow
	case strings.HasPrefix(key, "query-"):
		return d.verdict == verdictAllow && grpc
	case key == "client-add-if-absent" || key == "client-set-if-exists":
		// gRPC deny and error headers only know set (append=false) and add (append=true).
		return d.verdict == verdictAllow || !grpc
	}
	return true // client-set, client-add, metadata-set
}

// ignored lists the controls that have no place in the reply.
func (d decision) ignored(protocol string) []string {
	ignored := []string{}
	if d.invalid != "" {
		return ignored
	}
	for key := range d.controls {
		if !d.applies(key, protocol) {
			ignored = append(ignored, key)
		}
	}
	slices.Sort(ignored)
	return ignored
}

func (d decision) wait(ctx context.Context) error {
	if d.delay == 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
