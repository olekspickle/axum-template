.PHONY: docs test lint build build-release tag run-local

.ONESHELL: # Use one shell per target
SHELL := /bin/bash
# Stop excecution on any error
.SHELLFLAGS = -ec

docs:
	cargo docs

test:
	echo $(PKG)

lint:
	cargo clippy -- -D warnings
	cargo fmt --all -- --check

build:
	cargo fetch
	cargo build --target=x86_64-unknown-linux-musl

build-release:
	cargo fetch
	cargo build --target=x86_64-unknown-linux-musl --release

pack: build
	docker build -t axum-template:local .

tag: pack
	# todo: user can be sub-d with
	# git config --get user.name | cut -d " " -f 1
	# and version with
	# cargo pkgid | grep -oP '#\K[^#]+$'
	docker tag axum-template:local alekspickle/axum-template:v0.1.0

run-docker-restricted: pack
	docker run -d -p 7777:7777 \
	--rm --name axum-template --hostname axum-template \
	--cpus="0.25" --memory="0.5g" axum-template:local
