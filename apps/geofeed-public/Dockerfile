FROM nginx:1.27.1-alpine

RUN apk add --no-cache gettext
COPY apps/geofeed-public/public /usr/share/nginx/html
COPY apps/geofeed-public/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/geofeed-public/05-white-label.sh /docker-entrypoint.d/05-white-label.sh

RUN chmod 0755 /docker-entrypoint.d/05-white-label.sh \
    && rm -f /usr/share/nginx/html/*.csv /usr/share/nginx/html/geofeed-manifest.json
