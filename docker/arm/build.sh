#!/usr/bin/env bash
set -eu -o pipefail

main() {
    cd "$(git rev-parse --show-toplevel)"

    local image_name=axum-template-cross-arm
    local rust_toolchain=stable

    docker buildx build \
        --load \
        --build-arg RUST_TOOLCHAIN="$rust_toolchain" \
        --tag $image_name:latest \
        --file docker/arm/Dockerfile.cross \
        .
}

main "$@"
