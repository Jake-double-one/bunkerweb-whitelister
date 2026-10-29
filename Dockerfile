# syntax=docker/dockerfile:1.7
# Pinned to the current Python release line; Dependabot bumps the tag, CI rebuilds and scans it.
ARG PYTHON_IMAGE=python:3.14-slim

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="bunkerweb-whitelister" \
      org.opencontainers.image.description="Password-protected front end for BunkerWeb's global IP whitelist" \
      org.opencontainers.image.source="https://github.com/Jake-double-one/bunkerweb-whitelister" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONHASHSEED=random \
    PATH="/opt/venv/bin:$PATH" DATA_DIR=/data LISTEN_HOST=0.0.0.0 LISTEN_PORT=8080

# Latest Debian security patches, then drop everything the image does not need at runtime.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends tzdata \
 && apt-get purge -y --auto-remove \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /root/.cache \
 && pip uninstall -y pip setuptools wheel 2>/dev/null || true \
 && rm -rf /usr/local/lib/python3*/ensurepip \
 && groupadd --system --gid 10001 whitelister \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin whitelister \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root whitelister ./whitelister

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request,os; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('LISTEN_PORT','8080'), timeout=4).status == 200 else 1)"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "whitelister"]
