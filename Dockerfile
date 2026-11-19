FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY migrations migrations
COPY src src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* && useradd --system --home /data relay && mkdir /data && chown relay /data
COPY --from=build /src/target/release/fliks-relay /usr/local/bin/fliks-relay
USER relay
ENV RELAY_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["fliks-relay"]
CMD ["serve"]
