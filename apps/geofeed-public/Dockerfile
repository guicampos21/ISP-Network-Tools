FROM nginx:1.27.1-alpine

RUN apk add --no-cache gettext
COPY apps/geofeed-public/public /usr/share/nginx/html-static
COPY apps/geofeed-public/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/geofeed-public/05-white-label.sh /docker-entrypoint.d/05-white-label.sh

RUN mkdir -p /usr/share/nginx/html \
    && chmod 0755 /docker-entrypoint.d/05-white-label.sh
