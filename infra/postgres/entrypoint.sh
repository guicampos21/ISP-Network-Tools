#!/bin/sh
set -eu

runtime_dir=/tmp/isp-network-tools-postgres-secrets
install -d -o postgres -g postgres -m 0700 "$runtime_dir"

copy_secret() {
    name="$1"
    source="/run/secrets/$name"
    target="$runtime_dir/$name"
    if [ -f "$source" ]; then
        install -o postgres -g postgres -m 0400 "$source" "$target"
    fi
}

copy_secret postgres_password
copy_secret core_db_password
copy_secret geofeed_db_password
copy_secret health_db_password

export POSTGRES_PASSWORD_FILE="$runtime_dir/postgres_password"
export CORE_DB_PASSWORD_FILE="$runtime_dir/core_db_password"
export GEOFEED_DB_PASSWORD_FILE="$runtime_dir/geofeed_db_password"
export HEALTH_DB_PASSWORD_FILE="$runtime_dir/health_db_password"

if [ "$#" -eq 0 ]; then
    set -- postgres
fi
exec /usr/local/bin/docker-entrypoint.sh "$@"
