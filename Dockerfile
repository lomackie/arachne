FROM rust:alpine AS builder
WORKDIR /build
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.21
COPY --from=builder /build/target/release/arachne /usr/local/bin/arachne
