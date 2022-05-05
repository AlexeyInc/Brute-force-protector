BIN_BF_PROTECTOR := "./bin/bf-protector"
BIN_BF_PROTECTOR_CLI := "./bin/bf-cli"

GIT_HASH := $(shell git log --format="%h" -n 1)
LDFLAGS := -X main.release="develop" -X main.buildDate=$(shell date -u +%Y-%m-%dT%H:%M:%S) -X main.gitHash=$(GIT_HASH)

install-lint-deps:
	(which golangci-lint > /dev/null) || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.45.2

lint: install-lint-deps
	golangci-lint run ./...

build:
	go build -v -o $(BIN_BF_PROTECTOR) ./cmd/bf-protector;

build-cli:
	go build -v -o $(BIN_BF_PROTECTOR_CLI) ./cmd/cli;

run-local: build
	$(BIN_BF_PROTECTOR) -config ./configs/bf-protector_config.toml -log ./log/logs.log

redis-run:
	docker run --name redis-test-instance -p 6379:6379 -e REDIS_PASSWORD=secret123 -d redis

clean-cache:
	go clean -cache

test: clean-cache
	go test -v -count=2 -race -timeout=10s ./internal/app

run-integration-tests:
	cd deployments; docker-compose -f docker-compose.yml -f docker-compose.test.yml up \
		--exit-code-from integration_tests

integration-test: run-integration-tests
	cd deployments; docker-compose down --remove-orphans

grpc-gen:
	cd api; buf generate

run:
	cd deployments; docker-compose up

stop:
	cd deployments; docker-compose down

.PHONY: grpc-gen build build-cli run-local run-cli run stop test integration-test redis-run