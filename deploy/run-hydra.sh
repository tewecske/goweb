#!/bin/sh
# Runs Ory Hydra, the OAuth 2.0 / OpenID Connect server for single sign-on, as
# a container on the host network.
#
#   deploy/run-hydra.sh migrate ENV_FILE   apply Hydra's database migrations
#                                          (first deployment, and before each upgrade)
#   deploy/run-hydra.sh start ENV_FILE     (re)start Hydra
#   deploy/run-hydra.sh stop               stop and remove it
#
# ENV_FILE holds the settings and secrets; start from deploy/env/hydra.env.example
# and keep the real file out of Git (mode 600). Hydra listens on 127.0.0.1:24444
# (public API, reached through your tunnel or proxy) and 127.0.0.1:24445 (admin
# API, which can sign anyone in: never expose it); the ports come from
# SERVE_PUBLIC_PORT and SERVE_ADMIN_PORT in the env file. See docs/deployment.md.
set -eu

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${HYDRA_IMAGE:-oryd/hydra:v26.2.0}"
NAME="${HYDRA_CONTAINER:-goweb-hydra}"
config="$(cd "$(dirname "$0")" && pwd)/hydra/hydra.yml"

usage() {
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

env_file() {
	[ "$#" -ge 1 ] && [ -f "$1" ] || { echo "missing ENV_FILE" >&2; usage; }
	if [ -n "$(find "$1" -perm /077 2>/dev/null)" ]; then
		echo "warning: $1 is readable by other users; chmod 600 it" >&2
	fi
}

case "${1:-}" in
migrate)
	env_file "${2:-}"
	"$ENGINE" run --rm --network host --env-file "$2" "$IMAGE" migrate sql up -e --yes
	;;
start)
	env_file "${2:-}"
	"$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
	"$ENGINE" run -d --name "$NAME" --restart unless-stopped --network host \
		--read-only --cap-drop ALL --security-opt no-new-privileges \
		--env-file "$2" -v "$config:/etc/hydra/hydra.yml:ro" \
		"$IMAGE" serve all --config /etc/hydra/hydra.yml
	;;
stop)
	"$ENGINE" rm -f "$NAME"
	;;
*)
	usage
	;;
esac
