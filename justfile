set shell := ["bash", "-ec"]

crate := "axum-template"

# Generate self-signed SSL certificate for local HTTPS
cert:
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 \
        -keyout key.pem -out cert.pem \
        -subj "/CN=localhost" \
        -addext "subjectAltName = DNS:localhost"

# Open cargo docs
docs:
    cargo doc --open

# Run lints (clippy, fmt, machete)
lint:
    cargo clippy -- -D warnings
    cargo fmt --all -- --check
    cargo machete

# Run tests
test:
    cargo test

# Run the server (SQLite)
run:
    cargo run

# Build Docker image
pack:
    docker build -t {{crate}}:local .

# Tag Docker image
tag: pack
    docker tag {{crate}}:local olekspickle/{{crate}}:v0.1.0

# Run with SurrealDB via Docker Compose
run-surreal:
    docker compose -f compose.yml up --build

# Run Docker container with resource limits
run-docker-restricted: pack
    docker run -d \
        -p 7777:7777 \
        --hostname {{crate}} \
        --cpus="0.25" --memory="0.5g" \
        -e $log_level \
        {{crate}}:local
