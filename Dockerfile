# Base image with Rust and Alpine
FROM rust:1.81-alpine3.20 AS builder

# Install system dependencies and tools needed for Rust and your project
RUN apk update && \
    apk add --no-cache \
    # For pcsc dependency
    pcsc-lite-dev \
    # For tracing-attributes dependency (needs crti.o)
    musl-dev \
    # For OpenSSL dependency
    pkgconf \
    openssl-dev \
    gcc \
    make \
    perl-dev \
    # For cargo-msrv
    openssl-libs-static && \
    # Install clippy
    rustup component add clippy && \
    # Install cargo-audit and cargo-msrv
    cargo install --version 0.20.1 cargo-audit && \
    cargo install --version 0.15.1 cargo-msrv
