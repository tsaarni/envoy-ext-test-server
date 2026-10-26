IMAGE ?= envoy-ext-test-server:latest

build:
	CGO_ENABLED=0 go build -o envoy-ext-test-server .

container:
	docker build -t $(IMAGE) .

kind-load: container
	kind load docker-image $(IMAGE) --name contour

update-deps:
	go get -u ./...
	go mod tidy

clean:
	rm -f envoy-ext-test-server
