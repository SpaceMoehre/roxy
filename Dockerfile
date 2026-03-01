# syntax=docker/dockerfile:1.7

FROM rust:1.89-bookworm AS builder

WORKDIR /src

# Build-time packages used by some transitive crates and TLS stacks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        cmake \
        make \
        pkg-config \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY plugins ./plugins
COPY python/roxy-plugin-sdk ./python/roxy-plugin-sdk

RUN cargo build --release -p roxy

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin roxy

WORKDIR /app

COPY --from=builder /src/target/release/roxy /usr/local/bin/roxy
COPY --from=builder /src/plugins ./plugins
COPY --from=builder /src/python/roxy-plugin-sdk ./python/roxy-plugin-sdk

RUN mkdir -p /data \
    && chown -R roxy:roxy /app /data

ENV ROXY_PROXY_BIND=0.0.0.0:8080
ENV ROXY_API_BIND=0.0.0.0:3000
ENV ROXY_WS_BIND=0.0.0.0:3001
ENV ROXY_DATA_DIR=/data
ENV ROXY_PLUGIN_DIR=/app/plugins

EXPOSE 8080 3000 3001
VOLUME ["/data"]

USER roxy

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["roxy"]
