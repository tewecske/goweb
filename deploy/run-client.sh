#!/bin/sh
# Runs one client app (GOWEB_AUTH_MODE=client). Run it once per app; NAME makes
# the container name (goweb-client-NAME) and keeps the apps apart.
#
#   deploy/run-client.sh start NAME ENV_FILE
#   deploy/run-client.sh stop NAME
#
# Start from deploy/env/client.env.example, and register the app in Hydra with
# deploy/register-client.sh first. Image: GOWEB_IMAGE (pin a tag).
set -eu
dir="$(cd "$(dirname "$0")" && pwd)"
valid_name() { case "$1" in "" | *[!a-z0-9-]*) return 1 ;; esac; }
case "${1:-}" in
start) [ "$#" -eq 3 ] && valid_name "$2" || { echo "usage: $0 start NAME ENV_FILE (NAME: a-z, 0-9, -)" >&2; exit 2; }
	exec "$dir/run-goweb.sh" start "goweb-client-$2" "$3" ;;
stop) [ "$#" -eq 2 ] && valid_name "$2" || { echo "usage: $0 stop NAME" >&2; exit 2; }
	exec "$dir/run-goweb.sh" stop "goweb-client-$2" ;;
*) echo "usage: $0 start NAME ENV_FILE | stop NAME" >&2; exit 2 ;;
esac
