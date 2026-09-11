BINARY_NAME := goweb
GO := go

.PHONY: build clean fmt-check test vet assets check run

build:
	mkdir -p bin
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/web

assets:
	npm run build:css
	npm run check:assets

clean:
	rm -rf bin coverage.out coverage.html

fmt-check:
	test -z "$$(gofmt -l .)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: assets fmt-check vet test

run:
	$(GO) run ./cmd/web
