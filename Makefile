BINARY_NAME := goweb
GO := go

.PHONY: build clean fmt-check test vet check run

build:
	mkdir -p bin
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

clean:
	rm -rf bin coverage.out coverage.html

fmt-check:
	test -z "$$(gofmt -l .)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: fmt-check vet test

run:
	$(GO) run ./cmd/$(BINARY_NAME)
