#!/bin/sh
# Runs the single sign-on provider (GOWEB_AUTH_MODE=provider): the sign-in
# pages and the /sso/* routes Hydra redirects to. One per environment.
#
#   deploy/run-provider.sh start ENV_FILE
#   deploy/run-provider.sh stop
#
# Start from deploy/env/provider.env.example. Image: GOWEB_IMAGE (pin a tag).
set -eu
dir="$(cd "$(dirname "$0")" && pwd)"
case "${1:-}" in
start) [ "$#" -eq 2 ] || { echo "usage: $0 start ENV_FILE" >&2; exit 2; }
	exec "$dir/run-goweb.sh" start "${PROVIDER_CONTAINER:-goweb-provider}" "$2" ;;
stop) exec "$dir/run-goweb.sh" stop "${PROVIDER_CONTAINER:-goweb-provider}" ;;
*) echo "usage: $0 start ENV_FILE | stop" >&2; exit 2 ;;
esac
