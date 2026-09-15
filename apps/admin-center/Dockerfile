FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/apps/admin-center:/app/packages

RUN useradd --system --uid 10001 --create-home --home-dir /app admincenter

WORKDIR /app
COPY apps/admin-center/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY apps/admin-center/geofeed_admin ./apps/admin-center/geofeed_admin
COPY apps/admin-center/wsgi.py ./apps/admin-center/wsgi.py
COPY apps/admin-center/docker-entrypoint.sh /usr/local/bin/isp-admin-center-entrypoint
COPY packages/isp_shared ./packages/isp_shared

RUN mkdir -p /data /publish /backups \
    && chown -R admincenter:admincenter /app /data /publish /backups \
    && chmod 0755 /usr/local/bin/isp-admin-center-entrypoint

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/isp-admin-center-entrypoint"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "wsgi:app"]
