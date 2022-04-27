BIN_BF_PROTECTOR := "./bin/bf-protector"
BIN_BF_PROTECTOR_CLI := "./bin/bf-cli"

install-lint-deps:
	(which golangci-lint > /dev/null) || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.45.2

lint: install-lint-deps
	golangci-lint run ./...

build:
	go build -v -o $(BIN_BF_PROTECTOR) ./cmd/bf-protector;

build-cli:
	go build -v -o $(BIN_BF_PROTECTOR_CLI) ./cmd/cli;

run: build
	$(BIN_BF_PROTECTOR) -config ./configs/bf-protector_config.toml -lists ./assets/

test:
	go test -v -count=1 -race -timeout=10s ./internal/app

grpc-gen:
	cd api; buf generate

.PHONY: build build-cli grpc-gen test run run-cli