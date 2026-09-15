#!/bin/sh
set -eu

template_dir=/usr/share/nginx/html
for file in "$template_dir/index.html" "$template_dir/feed.html"; do
  [ -f "$file" ] || continue
  temp_file="$file.tmp"
  envsubst '${COMPANY_NAME} ${SUITE_NAME} ${ADMIN_BASE_URL} ${PUBLIC_BASE_URL} ${PUBLIC_CONTACT_EMAIL}' < "$file" > "$temp_file"
  mv "$temp_file" "$file"
done
