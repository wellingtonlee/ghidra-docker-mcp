FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=12.0.4
ENV GHIDRA_DATE=20260303
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    python3.12 \
    python3.12-venv \
    python3-pip \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/jvm/java-21-openjdk-* /usr/lib/jvm/java-21-openjdk

# Download and install Ghidra
# NOTE: Update SHA256 and URL once Ghidra 12.0.4 is released.
# If the version isn't available yet, adjust GHIDRA_VERSION/DATE above.
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip

# Build decompiler from source if not available for current architecture (e.g., arm64)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then PLATFORM="linux_x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then PLATFORM="linux_arm_64"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    DECOMP_DIR="${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler" && \
    chmod +x ${DECOMP_DIR}/os/*/decompile* 2>/dev/null || true && \
    if [ ! -f "${DECOMP_DIR}/os/${PLATFORM}/decompile" ]; then \
        echo "Decompiler not found for ${PLATFORM}, building from source..." && \
        apt-get update && apt-get install -y --no-install-recommends g++ make && \
        cd "${DECOMP_DIR}/src/decompile/cpp" && \
        make OSDIR=${PLATFORM} ARCH_TYPE= ghidra_opt && \
        mkdir -p "${DECOMP_DIR}/os/${PLATFORM}" && \
        cp ghidra_opt "${DECOMP_DIR}/os/${PLATFORM}/decompile" && \
        chmod +x "${DECOMP_DIR}/os/${PLATFORM}/decompile" && \
        make clean && \
        apt-get purge -y g++ make && apt-get autoremove -y && \
        rm -rf /var/lib/apt/lists/*; \
    fi && \
    test -x "${DECOMP_DIR}/os/${PLATFORM}/decompile" \
    || (echo "FATAL: decompiler not found for ${PLATFORM}" && \
        ls -la ${DECOMP_DIR}/os/ && exit 1)

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
