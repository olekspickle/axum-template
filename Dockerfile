# Run detached and remove container when it stopped
# Warning: Docker logs can mess up current terminal pane if not detached
#
# docker build -t axum-template:local .
# docker run -d -p 8000:8000 --rm --name axum-template --hostname axum-template

############################CACHE##############################################

FROM docker.io/rust:1.68.2-slim-bullseye AS builder

# it is common to name cached image `build` but this messes up
# rocket's fileserver which is configured in compile-time,
# so the build image and resulting image WORKDIR should match
WORKDIR /app

# copy the project
COPY . .

# 1. install stable Rust
# 2. run release build with cached rustup, cargo registry and target build artifacts
# 3. copy release binary with compressed debug symbols to the root
RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    set -eux; \
	rustup install stable; \
    cargo build --release; \
    objcopy --compress-debug-sections target/release/axum-template ./axum-template

################################################################################

FROM docker.io/debian:bullseye-slim

WORKDIR /app

# copy serer files
COPY --from=builder /app/axum-template ./axum-template
CMD ./axum-template
