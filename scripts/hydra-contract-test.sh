#!/bin/sh
# Runs the Hydra contract test (tests/hydra_integration_test.go) against a
# throwaway in-memory Hydra, so it needs no database and does not touch the
# development stack. Hydra uses host networking and ports 14444 and 14445,
# because the test receives Hydra's back-channel logout on a loopback listener.
set -eu

name=goweb-hydra-contract
image="oryd/hydra:v26.2.0"
public=http://127.0.0.1:14444
admin=http://127.0.0.1:14445

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
cleanup

docker run -d --rm --network host --name "$name" \
	-e DSN=memory \
	-e URLS_SELF_ISSUER="$public" \
	-e URLS_LOGIN=http://127.0.0.1:1/sso/login \
	-e URLS_CONSENT=http://127.0.0.1:1/sso/consent \
	-e URLS_LOGOUT=http://127.0.0.1:1/sso/logout \
	-e SERVE_PUBLIC_HOST=127.0.0.1 -e SERVE_PUBLIC_PORT=14444 \
	-e SERVE_ADMIN_HOST=127.0.0.1 -e SERVE_ADMIN_PORT=14445 \
	-e SECRETS_SYSTEM=0123456789abcdef0123456789abcdef \
	"$image" serve all --dev >/dev/null

i=0
until curl -fs "$admin/health/ready" >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 30 ]; then
		echo "Hydra did not become ready" >&2
		docker logs "$name" 2>&1 | tail -5 >&2
		exit 1
	fi
	sleep 1
done

GOWEB_HYDRA_TEST_ADMIN_URL="$admin" GOWEB_HYDRA_TEST_ISSUER_URL="$public" \
	go test -tags=integration -count=1 -run Hydra ./tests/
