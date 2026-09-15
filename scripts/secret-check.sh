#!/usr/bin/env bash
set -euo pipefail

if command -v rg >/dev/null 2>&1; then
  matches="$(rg -n --hidden \
    -g '!.git' \
    -g '!*.lock' \
    -g '!.env' \
    -g '!.local/**' \
    -g '!**/secrets/**' \
    -g '!**/tests/**' \
    -g '!apps/geofeed-public/public/*.html' \
    -g '!apps/admin-center/geofeed_admin/static/*.js' \
    -e '(client_secret|password|access_token|api[_-]?key)[[:space:]]*[:=][[:space:]]*\"[A-Za-z0-9_+/=-]{12,}\"' \
    -e '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' . || true)"
else
  matches=""
fi

if [ -n "$matches" ]; then
  echo "$matches"
  echo "Possível segredo encontrado no conteúdo versionado."
  exit 1
fi

echo "Nenhum padrão de segredo encontrado pelo verificador local."
