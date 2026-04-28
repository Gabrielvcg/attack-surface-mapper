#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v pwsh >/dev/null 2>&1; then
  echo "PowerShell 7+ (pwsh) is required to run this cross-platform wrapper." >&2
  echo "Install it or run scripts/validate_elasticsearch_local.ps1 from PowerShell." >&2
  exit 1
fi

exec pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/validate_elasticsearch_local.ps1" "$@"
