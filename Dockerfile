FROM rust:alpine AS builder
WORKDIR /build
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cp target/release/arachne /tmp/arachne && \
    cp target/release/arachne-agent /tmp/arachne-agent

FROM alpine:3.21
COPY --from=builder /tmp/arachne /usr/local/bin/arachne
COPY --from=builder /tmp/arachne-agent /usr/local/bin/arachne-agent
