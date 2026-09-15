FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/apps/isp-network-health/src:/app/apps/isp-network-health:/app/packages

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates dnsutils whois \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10002 --create-home --home-dir /app isphealth

WORKDIR /app
COPY apps/isp-network-health/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY apps/isp-network-health/src ./apps/isp-network-health/src
COPY apps/isp-network-health/isp_health ./apps/isp-network-health/isp_health
COPY apps/isp-network-health/docker-entrypoint.sh /usr/local/bin/isp-network-health-entrypoint
COPY packages/isp_shared ./packages/isp_shared

RUN mkdir -p /app/reports \
    && chown -R isphealth:isphealth /app \
    && chmod 0755 /usr/local/bin/isp-network-health-entrypoint

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/isp-network-health-entrypoint"]
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "isp_health.web:app"]
