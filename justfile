set shell := ["bash", "-ec"]

crate := "axum-template"

cert: # Generate self-signed SSL certificate for local HTTPS
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 \
        -keyout key.pem -out cert.pem \
        -subj "/CN=localhost" \
        -addext "subjectAltName = DNS:localhost"

lint:
    cargo clippy -- -D warnings
    cargo fmt --all -- --check
    cargo machete

cross-image: # Build cross-compilation Docker image
    ./docker/arm/build.sh

cross-build-pi: # Requires: cargo install cross + cross-image
    cross build --release --target aarch64-unknown-linux-gnu

run-surreal:
    docker compose -f docker/compose.yml up --build

pack: # Build Docker image locally
    docker build -t {{crate}}:local -f docker/Dockerfile.run .

tag: pack
    docker tag {{crate}}:local olekspickle/{{crate}}:v0.1.0

# Run Docker container with resource limits
run-docker-restricted: pack
    docker run -d \
        -p 7777:7777 \
        --hostname {{crate}} \
        --cpus="0.25" --memory="0.5g" \
        -e $log_level \
        {{crate}}:local
