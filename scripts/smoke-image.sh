#!/usr/bin/env bash
# Smoke-test a built WebVigil CLI image (CI and the release workflow run the same checks).
#
# Usage: scripts/smoke-image.sh <image> [platform]
#
# It proves the image starts, runs as an unprivileged user, carries its OCI labels, and that the
# packaged data files (the HTML report template) are inside it. Nothing here touches the network.
set -euo pipefail

image="${1:?usage: smoke-image.sh <image> [platform]}"
platform_args=()
if [ -n "${2:-}" ]; then
  platform_args=(--platform "$2")
fi
run() { docker run --rm "${platform_args[@]}" "$@"; }

echo "== version"
run "$image" version

echo "== the check catalogue loads"
run "$image" list-checks > /dev/null

echo "== runs as an unprivileged user"
uid="$(run --entrypoint id "$image" -u)"
if [ "$uid" = "0" ]; then
  echo "error: the image runs as root" >&2
  exit 1
fi

echo "== OCI labels"
for label in org.opencontainers.image.source org.opencontainers.image.licenses; do
  value="$(docker image inspect "$image" --format "{{ index .Config.Labels \"$label\" }}")"
  if [ -z "$value" ]; then
    echo "error: the image has no $label label" >&2
    exit 1
  fi
  echo "$label=$value"
done

echo "== a saved scan re-renders offline (exercises the packaged HTML template)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
cat > "$workdir/scan.json" <<'JSON'
{"schema_version":1,"metadata":{"target":"https://example.com/","mode":"passive","scope":"host","tool_version":"0","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z","pages_scanned":1,"counts":{"INFO":0,"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}},"findings":[],"errors":[],"warnings":[]}
JSON
chmod -R a+rwX "$workdir" # the image's user (uid 10001) must be able to read the mount
run -v "$workdir:/work" "$image" report /work/scan.json --format html | grep -qi "<html"

echo "ok: $image passed the smoke test"
