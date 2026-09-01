# syntax=docker/dockerfile:1
FROM rust:1.80-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY examples ./examples
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ferrumdns /usr/local/bin/ferrumdns
COPY examples/simple.yaml /etc/ferrumdns/config.yaml
EXPOSE 53/udp 53/tcp 9090
ENTRYPOINT ["ferrumdns", "start", "-c", "/etc/ferrumdns/config.yaml"]
