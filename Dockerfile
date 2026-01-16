# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Install protobuf compiler for gRPC
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY benches ./benches

# Create dummy src to cache dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/prefixdctl.rs && \
    echo "" > src/lib.rs

# Build dependencies only (skip benchmarks for faster builds)
RUN cargo build --release --bins && rm -rf src

# Copy actual source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN touch src/lib.rs src/main.rs src/bin/prefixdctl.rs && \
    cargo build --release --bins

# Runtime stage - use same base as rust image for glibc compatibility
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /app/target/release/prefixd /usr/local/bin/
COPY --from=builder /app/target/release/prefixdctl /usr/local/bin/

# Copy migrations (needed for postgres)
COPY --from=builder /app/migrations ./migrations

# Create data directory
RUN mkdir -p /data /etc/prefixd

# Default config directory
ENV PREFIXD_CONFIG=/etc/prefixd

EXPOSE 8080 9090

ENTRYPOINT ["prefixd"]
CMD ["--config", "/etc/prefixd"]
