FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -o /envoy-ext-test-server .

FROM scratch
COPY --from=builder /envoy-ext-test-server /envoy-ext-test-server
ENTRYPOINT ["/envoy-ext-test-server"]
