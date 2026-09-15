#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
secret_dir="$(printenv SECRETS_DIR || true)"
if [ -z "$secret_dir" ]; then
  secret_dir="$repo_root/.local/secrets"
fi
umask 077
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"

for name in postgres_password core_db_password geofeed_db_password health_db_password app_secret_key health_secret_key sso_signing_secret setup_token; do
  if [ ! -s "$secret_dir/$name" ]; then
    openssl rand -hex 32 > "$secret_dir/$name"
    chmod 600 "$secret_dir/$name"
  fi
done

for name in entra_client_secret google_client_secret; do
  touch "$secret_dir/$name"
  chmod 600 "$secret_dir/$name"
done

echo "Arquivos de segredo prontos em $secret_dir."
echo "Preencha manualmente os segredos de provedores que forem utilizados."
