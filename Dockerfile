FROM python:3.12-slim

# net-snmp CLI tools are used for the SNMP polling. They are deliberately
# preferred over a pure-python SNMP stack: snmpbulkwalk handles every
# v2c/v3 auth+priv combination and every vendor quirk (Cisco per-VLAN
# community/context indexing included) without library churn.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        snmp \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Suppress net-snmp's "Cannot find module" noise: we walk numeric OIDs only.
RUN printf 'mibs :\n' > /etc/snmp/snmp.conf

# ── corporate TLS interception ──────────────────────────────────────────────
# Any PEM *.crt dropped into scanner/certs/ is added to the system trust store.
# Networks running Netskope / Zscaler / Palo Alto / FortiGate deep inspection
# re-sign HTTPS with a private CA, which otherwise breaks pip at build time.
# Generate the file with scripts/export-proxy-ca.{ps1,sh}.
# The directory ships empty (README only), so this is a no-op without a proxy.
COPY certs/ /usr/local/share/ca-certificates/
RUN find /usr/local/share/ca-certificates -type f ! -name '*.crt' -delete \
    && update-ca-certificates \
    && echo "trusted CAs: $(grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt)"

# pip, requests and pynetbox all default to certifi's bundle rather than the
# system store, so point them at the store explicitly.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    STATE_DIR=/app/state

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p /app/state \
    && chown -R scanner:scanner /app
USER scanner

# Declared last so that bumping the version does not invalidate the pip layer.
# org.opencontainers.image.source is what links a GHCR package back to its repo.
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="scanspot" \
      org.opencontainers.image.description="Network discovery that keeps NetBox current, from FortiGate REST and multi-vendor SNMP." \
      org.opencontainers.image.source="https://github.com/Thaumazonsrl/scanspot" \
      org.opencontainers.image.url="https://github.com/Thaumazonsrl/scanspot" \
      org.opencontainers.image.documentation="https://github.com/Thaumazonsrl/scanspot#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Thaumazon SRL" \
      org.opencontainers.image.version="${VERSION}"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "app.main"]
