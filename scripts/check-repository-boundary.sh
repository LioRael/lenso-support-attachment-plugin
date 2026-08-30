#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_root="$repository_root/crates/lenso-support-attachment-postgres-plugin"
configuration_schema="$plugin_root/configuration.schema.json"

if rg -n '"(minLength|maxLength|pattern|minItems|maxItems|uniqueItems|maximum)"' \
  "$configuration_schema"; then
  echo "Plugin configuration uses keywords outside the current App-plan schema subset" >&2
  exit 1
fi

if rg -n 'support_cases|support_case_messages' "$plugin_root"; then
  echo "Support Attachment must not access Support Case private tables" >&2
  exit 1
fi

if rg -n -i 'object_key|protected_key|DELETE[[:space:]]+FROM[[:space:]]+.*content' \
  "$plugin_root/src" "$plugin_root/migrations"; then
  echo "Support Attachment must not expose object keys or delete protected content" >&2
  exit 1
fi

rg -q 'lenso.support-attachment@1' \
  "$repository_root/crates/lenso-capability-support-attachment/capability.json"
rg -q 'lenso.support-case-authorization@1' "$repository_root/README.md"
rg -q 'lenso.content-vault@1' "$repository_root/README.md"
