#!/bin/sh
# Runs the OpenID Foundation relying-party conformance plans against the client
# app's token handling (internal/adapter/oidc) with a local copy of the suite.
# Manual check, not part of CI. Needs Docker, curl, and openssl.
#
#   scripts/oidc-conformance.sh up     start the suite (https://localhost.emobix.co.uk:8443)
#   scripts/oidc-conformance.sh run    run the three plans below and print one verdict per module
#   scripts/oidc-conformance.sh down   stop the suite
#
# The suite's own certificate has no subject alternative name, which Go
# rejects, so a throwaway certificate for localhost.emobix.co.uk is generated
# under .conformance/ (git-ignored) and mounted into the suite's nginx. The
# suite reaches the program's back-channel logout listener through the Docker
# bridge gateway. See docs/deployment.md.
set -eu

cd "$(dirname "$0")/.."
dir=.conformance
project=goweb-conformance
compose="docker compose -p $project -f $dir/docker-compose-prebuilt.yml -f $dir/override.yml"
suite=https://localhost.emobix.co.uk:8443
plans="oidcc-client-basic-certification-test-plan oidcc-client-rp-initiated-logout-rp-basic oidcc-client-back-channel-logout-rp-basic"

case "${1:-}" in
up)
	mkdir -p "$dir"
	[ -f "$dir/docker-compose-prebuilt.yml" ] ||
		curl -fsSL -o "$dir/docker-compose-prebuilt.yml" https://gitlab.com/openid/conformance-suite/-/raw/master/docker-compose-prebuilt.yml
	[ -f "$dir/suite.key" ] ||
		openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$dir/suite.key" -out "$dir/suite-cert.pem" \
			-subj "/CN=localhost.emobix.co.uk" -addext "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost" 2>/dev/null
	cat >"$dir/override.yml" <<YAML
services:
  nginx:
    volumes:
      - ./suite-cert.pem:/etc/ssl/certs/nginx-selfsigned.crt:ro
      - ./suite.key:/etc/ssl/private/nginx-selfsigned.key:ro
YAML
	$compose up -d
	i=0
	until curl -fs --cacert "$dir/suite-cert.pem" -o /dev/null "$suite/api/plan/available"; do
		i=$((i + 1))
		if [ "$i" -gt 90 ]; then echo "suite did not become ready" >&2; exit 1; fi
		sleep 2
	done
	echo "suite ready at $suite"
	;;
run)
	gateway=$(docker network inspect "${project}_default" --format '{{(index .IPAM.Config 0).Gateway}}')
	SSL_CERT_FILE="$PWD/$dir/suite-cert.pem" go build -o "$dir/oidcconformance" ./tests/oidcconformance
	for plan in $plans; do
		echo "== $plan"
		SSL_CERT_FILE="$PWD/$dir/suite-cert.pem" "$dir/oidcconformance" -plan "$plan" -listen "$gateway:8082"
	done
	;;
down)
	$compose down
	;;
*)
	echo "usage: $0 up|run|down" >&2
	exit 2
	;;
esac
