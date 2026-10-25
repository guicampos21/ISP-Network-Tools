#!/bin/sh
set -eu

template_dir=/usr/share/nginx/html
static_dir=/usr/share/nginx/html-static

# In production the image filesystem is read-only. The writable runtime
# volume receives only the two rendered public pages. Render from the baked
# templates every time so a reused volume cannot keep stale or default HTML.

for name in index.html feed.html; do
  file="$template_dir/$name"
  template="$static_dir/$name"
  [ -f "$template" ] || continue
  temp_file="$file.tmp"
  envsubst '${COMPANY_NAME} ${SUITE_NAME} ${ADMIN_BASE_URL} ${PUBLIC_BASE_URL} ${HEALTH_BASE_URL} ${PUBLIC_CONTACT_EMAIL}' < "$template" > "$temp_file"
  mv "$temp_file" "$file"
done
