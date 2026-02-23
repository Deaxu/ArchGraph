# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

ARG INSTALL_EXTRAS=""
RUN if [ -z "$INSTALL_EXTRAS" ]; then \
        pip install --no-cache-dir .; \
    else \
        pip install --no-cache-dir ".[$INSTALL_EXTRAS]"; \
    fi

# --- Stage 2: Runtime ---
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/archgraph /usr/local/bin/archgraph

WORKDIR /data
ENTRYPOINT ["archgraph"]
