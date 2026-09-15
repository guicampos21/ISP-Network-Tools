#!/bin/sh
set -eu

runtime_dir=/tmp/isp-network-tools-secrets
install -d -o isphealth -g isphealth -m 0700 "$runtime_dir"

copy_secret() {
    name="$1"
    source="/run/secrets/$name"
    target="$runtime_dir/$name"
    if [ -f "$source" ]; then
        install -o isphealth -g isphealth -m 0400 "$source" "$target"
    fi
}

copy_secret health_secret_key
copy_secret sso_signing_secret
copy_secret health_db_password

export SECRET_KEY_FILE="$runtime_dir/health_secret_key"
export SSO_SIGNING_SECRET_FILE="$runtime_dir/sso_signing_secret"
export DATABASE_PASSWORD_FILE="$runtime_dir/health_db_password"

exec setpriv --reuid=10002 --regid=10002 --init-groups "$@"
