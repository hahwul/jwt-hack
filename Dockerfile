# syntax=docker/dockerfile:1
FROM rust:1.87.0-alpine3.22 AS chef

WORKDIR /usr/src/project

RUN set -eux; \
    apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static pkgconf perl; \
    cargo install cargo-chef; \
    rm -rf $CARGO_HOME/registry

FROM chef as planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /usr/src/project/recipe.json .
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release

FROM alpine:3.22

# Create a non-root user and group
RUN addgroup -S app && adduser -S -G app app

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache openssl libgcc

COPY --from=builder /usr/src/project/target/release/jwt-hack .

# Change ownership of the binary to the non-root user
RUN chown -R app:app .

# Switch to the non-root user
USER app

CMD ["./jwt-hack"]
