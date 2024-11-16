.PHONY: docs test lint build build-release tag run-local

.ONESHELL: # Use one shell per target
SHELL := /bin/bash
# Stop excecution on any error
.SHELLFLAGS = -ec

crate=axum-template

docs:
	cargo docs --open

lint:
	cargo clippy -- -D warnings
	cargo fmt --all -- --check
	cargo machete

pack:
	# TODO: query crate name with
	# cargo pkgid | rev | cut -d'/' -f1 | rev | sed 's/#.*//'
	docker build -t $(crate):local .

tag: pack
	# TODO: user can be sub-d with
	# git config --get user.name | cut -d " " -f 1
	# and version with
	# cargo pkgid | grep -oP '#\K[^#]+$'
	docker tag $(crate):local olekspickle/$(crate):v0.1.0

log_level=RUST_LOG=info,axum_template=trace

run:
	$(log_level) cargo run

run-surreal:
	docker compose -f compose.yml up --build

run-docker-restricted: pack
	docker run -d \
		-p 7777:7777 \
		--hostname $(crate) \
		--cpus="0.25" --memory="0.5g" \
		-e $(log_level) \
		$(crate):local
