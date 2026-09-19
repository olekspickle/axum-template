set shell := ["bash", "-ec"]

crate := "axum-template"

# Dev convenience only: local `just run`/`just test` get a throwaway password.
# Production deployments set their own ADMIN_PASSWORD (see systemd/setup.sh).
export ADMIN_PASSWORD := env_var_or_default("ADMIN_PASSWORD", "admin")

cert: # Generate self-signed SSL certificate for local HTTPS
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 \
        -keyout key.pem -out cert.pem \
        -subj "/CN=localhost" \
        -addext "subjectAltName = DNS:localhost"

css: # Compile Tailwind CSS (requires node; rerun after editing templates/static/js classes)
    npm install
    npm run build:css

lint: check-templates
    cargo clippy -- -D warnings
    cargo fmt --all -- --check
    cargo machete

check-templates: # Fail if .generate templates drift from their live counterparts
    #!/usr/bin/env bash
    set -euo pipefail
    # Generated projects have no .generate (post-generate.rhai deletes it) — skip there.
    if [ ! -d .generate ]; then
        echo "no .generate directory — not the template repo, skipping"
        exit 0
    fi
    fail=0
    sub() {
        sed -e 's/[{][{]project-name[}][}]/axum-template/g' \
            -e 's/[{][{]crate_name[}][}]/axum_template/g' \
            -e 's/[{][{]authors[}][}]/olekspickle/g' \
            -e 's/[{][{]domain[}][}]/tunnel.example.com/g' \
            -e 's/{[%] raw [%]}//g' \
            -e 's/{[%] endraw [%]}//g' \
            -e 's/^version = ".*"/version = "MASKED"/' \
            -e 's/^authors = .*/authors = MASKED/' \
            -e '/Askama syntax is wrapped in raw blocks/d' "$1"
    }
    check() {
        if ! diff <(sub "$1") <(sub "$2") >/dev/null; then
            echo "DRIFT: $1 != $2"
            diff <(sub "$1") <(sub "$2") | head -30
            fail=1
        fi
    }
    check .generate/Cargo.toml.template Cargo.toml
    check .generate/src/main.rs.template src/main.rs
    check .generate/templates/head.html.template templates/head.html
    check .generate/Dockerfile.template docker/Dockerfile.run
    check .generate/compose.yml.template docker/compose.yml
    check .generate/.github/workflows/release.yaml.template .github/workflows/release.yaml
    check .generate/systemd/axum-template.service.template systemd/axum-template.service
    check .generate/systemd/cleanup.sh.template systemd/cleanup.sh
    check .generate/systemd/cloudflared-config.yml.template systemd/cloudflared-config.yml
    check .generate/systemd/cloudflared.service.template systemd/cloudflared.service
    check .generate/systemd/setup.sh.template systemd/setup.sh
    check .generate/tests/integration.rs.template tests/integration.rs
    check .generate/tests/surreal_db.rs.template tests/surreal_db.rs
    # README.md.template is intentionally excluded: the generated README differs by design.
    if [ "$fail" -eq 0 ]; then echo "templates in sync"; fi
    exit "$fail"

test: # Run the test suite (surreal tests are skipped unless a server is reachable)
    cargo test --all-targets

test-surreal: # Round-trip the SurrealDB backend against a throwaway server
    docker run -d --rm --name surreal-test -p 8000:8000 surrealdb/surrealdb:v3 start --user root --pass root memory
    cargo test --no-default-features --features surreal --all-targets; \
        docker stop surreal-test

build-pi: # Native aarch64 build (requires gcc-aarch64-linux-gnu)
    cargo build --release --target aarch64-unknown-linux-gnu

cross-image: # Build cross-compilation Docker image
    ./docker/arm/build.sh

cross-build-pi: # Requires: cargo install cross + cross-image
    cross build --release --target aarch64-unknown-linux-gnu

run-surreal:
    docker compose -f docker/compose.yml up --build

pack: # Build Docker image locally
    docker build -t {{crate}}:local -f docker/Dockerfile.run .

tag version: pack # Tag local image, e.g. `just tag v0.2.0`
    docker tag {{crate}}:local {{crate}}:{{version}}

# Run Docker container with resource limits
run-docker-restricted: pack
    docker run -d \
        -p 7777:7777 \
        --hostname {{crate}} \
        --cpus="0.25" --memory="0.5g" \
        -e $log_level \
        {{crate}}:local
