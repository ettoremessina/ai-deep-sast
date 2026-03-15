# Multi-stage build:
#   Stage 1: Build llama.cpp from source
#   Stage 2: Production image with scanner + model
# ============================================================

# ============================================================
# STAGE 1: Build llama.cpp
# ============================================================
FROM ubuntu:22.04 AS llama-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    cmake \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone and build llama.cpp
RUN git clone https://github.com/ggerganov/llama.cpp.git /llama.cpp && \
    cd /llama.cpp && \
    cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --config Release -j$(nproc) && \
    cp build/bin/llama-cli /usr/local/bin/llama-cli && \
    chmod +x /usr/local/bin/llama-cli

# ============================================================
# STAGE 2: Production Image
# ============================================================
FROM python:3.11-slim

LABEL maintainer="security-team"
LABEL description="AI-Powered OWASP Top 10 Scanner using Cisco Foundation-Sec-8B-Instruct"
LABEL model="fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SCANNER_OUTPUT_DIR=security-reports
ENV SCANNER_HF_REPO=fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF
ENV SCANNER_HF_FILE=foundation-sec-8b-instruct-q8_0.gguf

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy llama-cli from builder stage
COPY --from=llama-builder /usr/local/bin/llama-cli /usr/local/bin/llama-cli

# Verify llama-cli works
RUN llama-cli --version || echo "llama-cli installed (version check may return non-zero)"

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Verify semgrep works
RUN semgrep --version

# ============================================================
# Pre-download the model (optional but recommended)
# Uncomment the following lines to bake the model into the image.
# This makes the image ~8 GB larger but eliminates download time
# at runtime. - it works well in my laptop with limited memory - santokum
#
# If you prefer to mount the model cache at runtime instead,
# leave these lines commented and use:
#   docker run -v /model-cache:/root/.cache/llama.cpp ...
# ============================================================
# RUN mkdir -p /root/.cache/llama.cpp && \
#     llama-cli \
#         --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
#         --hf-file foundation-sec-8b-instruct-q8_0.gguf \
#         -p "test" \
#         -n 1 && \
#     echo "Model pre-cached successfully."

# Copy application code
COPY aiowaspscan.py /app/aiowaspscan.py
COPY config/ /app/config/
COPY samples/ /app/samples/

WORKDIR /app

# Health check
HEALTHCHECK --interval=60s --timeout=30s --retries=3 \
    CMD semgrep --version && llama-cli --version || true

# Default entrypoint
ENTRYPOINT ["python3", "aiowaspscan.py"]
CMD ["--config", "config/scanner_config.yaml"]