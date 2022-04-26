BIN_BF_PROTECTOR := "./bin/bf-protector"


build:
	go build -v -o $(BIN_BF_PROTECTOR) ./cmd/bf-protector;

run: build
	$(BIN_BF_PROTECTOR) -config ./configs/bf-protector_config.toml -lists ./assets/

test:
	go test -v -count=1 -race -timeout=10s ./internal/app

grpc-gen:
	cd api; buf generate

.PHONY: grpc-gen test