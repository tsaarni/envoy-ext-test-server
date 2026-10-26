# envoy-ext-test-server

A test server for Envoy's `ext_authz` filter, over gRPC and HTTP.

The request sent through Envoy carries instructions for the server, called controls, for example
`Authorization: x-authz status=403`. The server replies as instructed and records what Envoy sent in the check.
One process is one authz server. Run several processes for several behaviors.

## Running

Run directly from the repository:

```shell
go run github.com/tsaarni/envoy-ext-test-server@latest --name strict --grpc-addr :9001 --http-addr :9002 --metrics-addr :9100 \
  --scenario default='status=403' --scenario redirect='status=302 client-set=location:/login'
```

Or install the binary:

```shell
go install github.com/tsaarni/envoy-ext-test-server@latest
```

In a clone, `go test ./...` runs the tests and `make container` builds a container image.

Every flag can also be set with an environment variable: `EXT_TEST_` plus the flag name in uppercase with `-`
replaced by `_`. Flags override environment variables.

| flag | default | meaning |
|---|---|---|
| `--name` | `authz` | server name used in replies, logs and metrics |
| `--scenario NAME=CONTROLS` | | named set of controls, repeatable. `default` applies to every check. Env: `EXT_TEST_SCENARIO='default=status=403;redirect=status=302 client-set=location:/login'` (`;` separates scenarios) |
| `--grpc-addr`, `--http-addr` | `:9001`, `:9002` | listen addresses. Empty disables the listener |
| `--grpc-tls-cert`, `--grpc-tls-key`, `--grpc-tls-ca` | | gRPC TLS. Setting a CA enables mTLS |
| `--http-tls-cert`, `--http-tls-key`, `--http-tls-ca` | | HTTP TLS. Setting a CA enables mTLS |
| `--metrics-addr` | | serves `/metrics` without authentication. Empty disables |
| `--quiet` | `false` | no `CHECK` log lines |

## Examples

The HTTP server can be tried with curl, without Envoy:

```shell
curl -si localhost:9002/ -H 'Authorization: x-authz status=403'    # deny
curl -si 'localhost:9002/?x-authz=status=401+body=go%2520away'     # deny with text body, query carrier
curl -si localhost:9002/ -H 'x-authz: verdict=abort'               # connection dropped
curl -si localhost:9002/ -H 'x-authz: scenario=redirect tag=t1'    # 302 to /login
```

Common controls:

| test | controls |
|---|---|
| deny with challenge | `status=401 client-set=www-authenticate:Basic%20realm=test` |
| redirect | `status=302 client-set=location:/login` |
| identity header to backend | `upstream-set=x-user:alice` |
| strip a header before backend | `upstream-remove=cookie` |
| rewrite query (gRPC) | `query-set=user:alice query-remove=token` |
| timeout | `delay=2s` with an ext_authz timeout of 1s |
| server failure | `verdict=error` or `verdict=abort`, with and without `failure_mode_allow` |

## Controls

A control is a `key=value` pair. Pairs are separated by spaces or commas: `status=302 client-set=location:/login tag=t1`.

- Values are percent-decoded (`%20` space, `%2C` comma, `%25` percent).
- Header, query and metadata controls take `name:value`. The name ends at the first `:` after its first character,
  so `client-set=:path:/x` sets the header `:path`.
- Controls marked "list" can be repeated. For the others the last value wins.

| control | gRPC | HTTP |
|---|---|---|
| `verdict=allow\|deny\|error\|abort` | OK / `denied_response` / `error_response` / RPC fails with `Unavailable` | 200 / `status` / 5xx / connection dropped |
| `status=N` | HTTP status of deny or error, 200..599 | response status |
| `delay=2s` | wait before replying (Go duration) | same |
| `body=text` | body of deny or error. Default is the check record as JSON | same |
| `upstream-set=n:v` (list) | header to upstream, replaces | response header |
| `upstream-append=n:v` (list) | header to upstream, appended | response header |
| `upstream-remove=n` (list) | `headers_to_remove` | `x-envoy-auth-headers-to-remove` |
| `client-set=n:v` (list) | allow: `response_headers_to_add`, overwrite. Deny and error: response header | response header |
| `client-add=n:v` (list) | allow: append. Deny and error: appended header (Envoy drops these on deny) | response header |
| `client-add-if-absent=n:v` (list) | allow only | response header |
| `client-set-if-exists=n:v` (list) | allow only | response header |
| `query-set=k:v` (list) | `query_parameters_to_set` | not possible |
| `query-remove=k` (list) | `query_parameters_to_remove` | not possible |
| `metadata-set=k:v` (list) | `dynamic_metadata`, string values | response header, for `dynamic_metadata_from_headers` |
| `tag=t1` | label in replies, record and metrics. Up to 128 printable characters, no spaces | same |
| `scenario=name` | expands the scenario | same |

- Without `verdict`, status 200 allows and any other status denies, so `status=403` alone is a deny.
  Default statuses: deny 403, error 503.
- An invalid value, unknown control or unknown scenario is a deny with 400. The reason is in the record's `error`.
- A control that does not apply to the protocol and verdict is not sent and is listed in the record's `ignored`.
  For example `upstream-*` on deny, `query-*` on HTTP, `body` on allow.
- Header names and values are not validated, so Envoy's header mutation rules can be tested.
  The HTTP server drops invalid header names such as `:path`.

Controls are read from these carriers:

| carrier | how to send | gRPC | HTTP |
|---|---|---|---|
| `default` | `--scenario default='...'` | yes | yes |
| `context` | context extension `x-authz` in the route's `check_settings.context_extensions` | yes | no |
| `query` | `/path?x-authz=status=403+tag=t1` | yes | yes |
| `header` | `x-authz: status=403` | yes | only if `x-authz` is in `allowed_headers` |
| `authorization` | `Authorization: x-authz status=403` | yes | yes |

- Carriers are merged per control in the table order. A later carrier replaces the whole value, including lists.
- `scenario=name` expands a named scenario first. Other controls in the same carrier override it.
  Scenarios cannot contain `scenario=`.
- Other `Authorization` schemes (`Bearer`, `Basic`) are ignored.
- In the query carrier `+` is a space and percent-encoded values must be encoded twice (`body=go%2520away`).
  The parameter is passed on to the upstream unless removed with `query-remove=x-authz` (gRPC only).

## Replies

| verdict | gRPC | HTTP |
|---|---|---|
| `allow` | `OK` with `ok_response` | 200, no body |
| `deny` | `PERMISSION_DENIED` with `denied_response` | `status`, headers, body |
| `error` | `UNAVAILABLE` with `error_response` | 5xx (503 unless `status` is 5xx) |
| `abort` | RPC fails with `UNAVAILABLE` | connection dropped |

- Every reply except abort has `x-authz-server`, `x-authz-verdict` and, if tagged, `x-authz-tag`.
- Deny and error without `body` have `content-type: application/json` and the check record as body.
  A custom `body` has no content type, add one with `client-set=content-type:text/plain`.
- An HTTP server can only send response headers, so all header controls become response headers and the
  verb makes no difference.

What Envoy does with the reply:

- Deny: the client gets the status, headers and body as sent.
- Error and abort: Envoy returns `status_on_error` (default 403), or forwards the request with
  `failure_mode_allow`. A `delay` longer than the ext_authz timeout is also an error.
- HTTP 5xx is always an error for Envoy, even with `verdict=deny`.
- gRPC `error_response` needs Envoy 1.37 or later. Older versions treat it as a deny with 403.

Envoy configuration:

- The gRPC cluster needs HTTP/2.
- gRPC receives all request headers unless `allowed_headers` is set. HTTP only receives `Authorization`, method,
  path and host, plus `allowed_headers`.
- Context extensions, dynamic metadata and `attributes` in the check record are available with gRPC only.
- HTTP response headers are routed by `allowed_upstream_headers`, `allowed_upstream_headers_to_append`,
  `allowed_client_headers` (deny), `allowed_client_headers_on_success` (allow) and
  `dynamic_metadata_from_headers`.

## Check record

The check record is what the server received and decided. It is logged on every check and returned as the body of
deny and error replies, so the client can see what Envoy sent:

```shell
curl -sk https://<host>/ -H 'Authorization: x-authz status=403' | jq .request.headers
```

```json
{
  "server": "strict", "tag": "t1", "request_id": "…", "protocol": "grpc",
  "verdict": "deny", "status": 403, "error": "",
  "controls": {"status": {"values": ["403"], "carrier": "authorization"}},
  "ignored": [],
  "envoy_connection": {"tls": true, "sni": "authz.example.com", "client_cert": "CN=envoy"},
  "attributes": {
    "source": {"address": "10.0.0.1:5555"},
    "destination": {"address": "10.0.0.2:443"},
    "tls_sni": "echo.example.com",
    "context_extensions": {"x-authz": "tag=t1"}
  },
  "request": {
    "http_version": "HTTP/2", "method": "GET", "scheme": "https", "host": "…", "path": "/a?x=1",
    "headers_field": "headers", "body_size": 0, "body": "",
    "headers": {"x-dup": ["one,two"]}
  }
}
```

- `envoy_connection` describes the connection from Envoy to this server, not the client's.
- `attributes` is only present for gRPC. Peer certificates and the client SNI need `include_peer_certificate` and
  `include_tls_session` in the Envoy config.
- `request` is the client request as Envoy described it. `path` includes the query. `body` is the first 1024 bytes,
  and is only sent by Envoy with `with_request_body`.
- Envoy joins repeated client headers with `,` before the check (`"x-dup": ["one,two"]`). With
  `encode_raw_headers` they stay separate and `headers_field` is `header_map`.

## Logs and metrics

Logs are JSON, one object per line. Each check logs a `CHECK` line with the check record fields. The server name is
`instance` there. To find the checks for one test:

```shell
<log output> | jq -c 'select(.msg=="CHECK" and .tag=="t1")'
```

`--metrics-addr :9100` serves Prometheus metrics at `/metrics`, also with `--quiet`. There is no authentication,
so bind it to localhost or a test network. All `authz_*` metrics have a `name` label with the server name.

| metric | labels |
|---|---|
| `authz_checks_total` | `protocol`, `verdict`, `status`, `tag`, `host`, `path`, `sni`, `client_cert` |
| `authz_controls_total` | `control`, `carrier` |
| `authz_request_headers_total` | `header` |
| `authz_context_extensions_total` | `key`, `value` |
| `authz_check_duration_seconds` | `protocol`, `verdict` (histogram, includes `delay`) |

```shell
curl -s localhost:9100/metrics | grep '^authz_checks_total{.*tag="t1"'
```

Counters reset on restart, so compare values before and after a test or use a separate `tag` for each test.
Every distinct label combination is a new time series, so do not use a new `tag` per request in load tests.

## Terminology

| term | meaning |
|---|---|
| client request | the original request from the client to Envoy |
| check | Envoy's request to this server about one client request |
| control | one `key=value` in the check that tells the server how to reply |
| carrier | where a control came from: `default`, `scenario`, `context`, `query`, `header`, `authorization` |
| scenario | a named set of controls, defined with `--scenario` |
| verdict | what the server sent: `allow`, `deny`, `error`, `abort`, or `none` (nothing was sent) |
| upstream | the request Envoy forwards to the backend, only on allow |
| client | the response the client receives: the backend response on allow, Envoy's local reply on deny and error |
| check record | what the server received and sent in one check: the `CHECK` log line and the default deny body |

Verbs in control names:

| verb | meaning |
|---|---|
| `set` | overwrite the header, or add it if missing |
| `add` | add another header line |
| `append` | join the value to the existing header with `,`. Envoy drops it if the header is missing |
| `remove` | delete the header or query parameter |
