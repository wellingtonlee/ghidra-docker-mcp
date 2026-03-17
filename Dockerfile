FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=12.0.4
ENV GHIDRA_DATE=20260303
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    python3.12 \
    python3.12-venv \
    python3-pip \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
# NOTE: Update SHA256 and URL once Ghidra 12.0.4 is released.
# If the version isn't available yet, adjust GHIDRA_VERSION/DATE above.
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip

ENV PATH="${GHIDRA_INSTALL_DIR}:${PATH}"

# Create non-root user
RUN useradd -m -s /bin/bash ghidra
WORKDIR /home/ghidra

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python3.12 -m pip install --break-system-packages --no-cache-dir -e ".[dev]"

# Create directories for binaries and projects
RUN mkdir -p /home/ghidra/binaries /home/ghidra/projects \
    && chown -R ghidra:ghidra /home/ghidra

COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER ghidra

# Volumes
VOLUME ["/home/ghidra/binaries", "/home/ghidra/projects"]

ENTRYPOINT ["/entrypoint.sh"]
