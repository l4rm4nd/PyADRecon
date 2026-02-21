# Build stage
FROM python:3.12.4-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# Runtime stage
FROM python:3.12.4-slim
LABEL Maintainer="LRVT"

# Install only runtime libraries (not build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    libssl3 \
    libxml2 \
    libxslt1.1 \
    libkrb5-3 \
    krb5-user \
    && rm -rf /var/lib/apt/lists/*

# Configure OpenSSL to enable legacy providers (required for MD4/NTLM)
RUN mkdir -p /etc/ssl && \
    cat > /etc/ssl/openssl.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOF

# Set environment variable to use legacy OpenSSL config
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application
COPY pyadrecon.py /app/
COPY dashboard_generator.py /app/

WORKDIR /app
ENTRYPOINT ["python", "pyadrecon.py"]
