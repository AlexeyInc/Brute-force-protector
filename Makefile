grpc-gen:
	cd api; buf generate

test:
	go test -v -count=1 -race -timeout=10s ./internal/app

.PHONY: grpc-gen test