#!/usr/bin/env bash
set -euo pipefail

read_secret() {
  local path="$1"
  tr -d '\r\n' < "$path"
}

create_role_and_database() {
  local role="$1"
  local password_file="$2"
  local database="$3"
  local password
  password="$(read_secret "$password_file")"

  psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set ON_ERROR_STOP=1 \
    --set role_name="$role" \
    --set role_password="$password" \
    --set database_name="$database" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'role_name', :'role_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'role_name')\gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'role_name', :'role_password')\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'database_name', :'role_name')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'database_name')\gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'database_name', :'role_name')\gexec
SQL
}

create_role_and_database "$CORE_DB_USER" "${CORE_DB_PASSWORD_FILE:-/run/secrets/core_db_password}" isp_core
create_role_and_database "$GEOFEED_DB_USER" "${GEOFEED_DB_PASSWORD_FILE:-/run/secrets/geofeed_db_password}" geofeed
create_role_and_database "$HEALTH_DB_USER" "${HEALTH_DB_PASSWORD_FILE:-/run/secrets/health_db_password}" isp_network_health
