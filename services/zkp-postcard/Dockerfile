# Pinned by digest. The floating nightly-slim tag moved to rustc 1.101.0-nightly (32dba69d6
# 2026-10-09), which panics (ICE) compiling p3-monty-31 at Plonky3 rev 27d59f73. This digest is the
# image the last successful build used (deployment c23dc8a6, 2026-10-08). Bump it deliberately,
# with a green prover-build run, never by tag drift.
FROM rustlang/rust:nightly-slim@sha256:00d1e943e1a348d479d89dbbbbd46268316b61437d1a98af055c23068cf45516 AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zkp-postcard /usr/local/bin/
ENV PORT=8080
EXPOSE 8080
CMD ["zkp-postcard"]
