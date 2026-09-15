#!/bin/sh
set -eu

runtime_dir=/tmp/isp-network-tools-secrets
install -d -o admincenter -g admincenter -m 0700 "$runtime_dir"

copy_secret() {
    name="$1"
    source="/run/secrets/$name"
    target="$runtime_dir/$name"
    if [ -f "$source" ]; then
        install -o admincenter -g admincenter -m 0400 "$source" "$target"
    fi
}

copy_secret app_secret_key
copy_secret sso_signing_secret
copy_secret setup_token
copy_secret core_db_password
copy_secret entra_client_secret
copy_secret google_client_secret

export SECRET_KEY_FILE="$runtime_dir/app_secret_key"
export SSO_SIGNING_SECRET_FILE="$runtime_dir/sso_signing_secret"
export SETUP_TOKEN_FILE="$runtime_dir/setup_token"
export DATABASE_PASSWORD_FILE="$runtime_dir/core_db_password"
export ENTRA_CLIENT_SECRET_FILE="$runtime_dir/entra_client_secret"
export GOOGLE_CLIENT_SECRET_FILE="$runtime_dir/google_client_secret"

exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
