BINARY_NAME := goweb
GO := go

.PHONY: build clean fmt-check test vet assets check run run-provider run-client db-up db-down sso-up sso-client

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
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; $(GO) run ./cmd/web

db-up:
	docker compose up -d

db-down:
	docker compose --profile sso down

# Ory Hydra for single sign-on (docs/sso-hydra-plan.md).
sso-up:
	docker compose --profile sso up -d --wait hydra sso-backchannel-relay

# Re-registers the development SSO client app and writes its settings to the
# git-ignored .env.client (the secret changes on every run).
sso-client:
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; umask 077; scripts/hydra-dev-client.sh > .env.client
	@echo "wrote .env.client; start the client app with: make run-client"

# The single sign-on provider (GOWEB_AUTH_MODE=provider) at SSO_DEV_PROVIDER_URL
# (default http://localhost:8080), using the main database from .env.
run-provider:
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; \
	url="$${SSO_DEV_PROVIDER_URL:-http://localhost:8080}"; \
	GOWEB_AUTH_MODE=provider GOWEB_PUBLIC_URL="$$url" GOWEB_HTTP_ADDR="$${SSO_DEV_BIND:-127.0.0.1}:$${url##*:}" \
	GOWEB_HYDRA_ADMIN_URL=http://127.0.0.1:4445 GOWEB_SSO_ISSUER_URL="$${SSO_DEV_ISSUER_URL:-http://127.0.0.1:4444}" \
	$(GO) run ./cmd/web

# A client app (GOWEB_AUTH_MODE=client) at SSO_DEV_CLIENT_URL (default
# http://127.0.0.1:8081) with its own goweb_client database; .env.client
# overrides .env.
run-client:
	@set -a; if [ -f .env ]; then . ./.env; fi; . ./.env.client; set +a; $(GO) run ./cmd/web
