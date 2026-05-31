FROM rust:slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools clang && rm -rf /var/lib/apt/lists/*

# Install nightly toolchain + rust-src + bpf target before copying source so
# this layer is cached independently of code changes.
COPY rust-toolchain.toml ./
RUN rustup show

# Install bpf-linker in its own layer so it's cached across code changes.
# Default features use aya-rustc-llvm-proxy to load LLVM 22 from the Rust
# toolchain's libLLVM.so, avoiding the need for a separate LLVM installation.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install bpf-linker

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY arachne-common ./arachne-common
COPY arachne-ebpf ./arachne-ebpf
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/release/arachne /tmp/arachne && \
    cp target/x86_64-unknown-linux-musl/release/arachne-agent /tmp/arachne-agent

FROM alpine:3.21
COPY --from=builder /tmp/arachne /usr/local/bin/arachne
COPY --from=builder /tmp/arachne-agent /usr/local/bin/arachne-agent
