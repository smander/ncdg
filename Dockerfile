FROM python:3.13-slim AS base

# Install build tools: native gcc + ARM64 cross-compiler + CVC5 for SMT-LIB backend testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    bc \
    binutils \
    bison \
    device-tree-compiler \
    file \
    flex \
    gcc \
    gcc-aarch64-linux-gnu \
    git \
    libc6-dev \
    libc6-dev-arm64-cross \
    libssl-dev \
    make \
    python3-pyelftools \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install CVC5 binary for SMT-LIB backend testing (non-fatal if download fails)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -q -O /usr/local/bin/cvc5 \
            https://github.com/cvc5/cvc5/releases/download/cvc5-1.2.0/cvc5-Linux-x86_64-static \
        && chmod +x /usr/local/bin/cvc5 \
        && echo "CVC5 installed (amd64)" \
        || echo "CVC5 download failed, skipping"; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -q -O /usr/local/bin/cvc5 \
            https://github.com/cvc5/cvc5/releases/download/cvc5-1.2.0/cvc5-Linux-arm64-static \
        && chmod +x /usr/local/bin/cvc5 \
        && echo "CVC5 installed (arm64)" \
        || echo "CVC5 download failed, skipping"; \
    else \
        echo "CVC5 not available for $ARCH, skipping"; \
    fi

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY pyproject.toml .
COPY cdg_lib/ cdg_lib/
COPY src/ src/
COPY tests/ tests/
COPY experiments/ experiments/
COPY firmware/ firmware/
COPY scripts/ scripts/
COPY run.sh .
RUN chmod +x run.sh

# Compile CDG-Bench: all 4 versions (try ARM64 cross-compile, fall back to native)
RUN for ver in v1.0 v1.1 v1.2 v1.3; do \
        outname="cdg_bench_$(echo $ver | tr '.' '')"; \
        aarch64-linux-gnu-gcc -O1 -g -fno-inline -static \
            -o /app/${outname}_arm64 /app/src/cdg_bench_${ver}.c 2>/dev/null \
        && echo "${ver}: ARM64 cross-compiled" \
        || (gcc -O1 -g -fno-inline \
            -o /app/${outname}_arm64 /app/src/cdg_bench_${ver}.c \
            && echo "${ver}: Native compiled"); \
    done

# Install package in editable mode
RUN pip install --no-cache-dir -e ".[dev]"

# Default: run full pipeline
ENTRYPOINT ["./run.sh"]
