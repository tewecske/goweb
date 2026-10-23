#!/bin/sh
# Shared by run-provider.sh and run-client.sh: runs one goweb container on the
# host network. Usage: run-goweb.sh start NAME ENV_FILE | run-goweb.sh stop NAME
set -eu

ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${GOWEB_IMAGE:-ghcr.io/tewecske/goweb:latest}"

case "${1:-}" in
start)
	name="$2"
	env_file="$3"
	[ -f "$env_file" ] || { echo "ENV_FILE not found: $env_file" >&2; exit 2; }
	if [ -n "$(find "$env_file" -perm /077 2>/dev/null)" ]; then
		echo "warning: $env_file is readable by other users; chmod 600 it" >&2
	fi
	"$ENGINE" rm -f "$name" >/dev/null 2>&1 || true
	# The app writes nothing to disk, needs no capabilities, and logs to stdout.
	"$ENGINE" run -d --name "$name" --restart unless-stopped --network host \
		--read-only --cap-drop ALL --security-opt no-new-privileges \
		--env-file "$env_file" "$IMAGE"
	;;
stop)
	"$ENGINE" rm -f "$2"
	;;
esac
