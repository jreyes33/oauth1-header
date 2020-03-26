.ONESHELL:
.PHONY: check clean build fmt clippy test doc

check: clean build fmt clippy test doc

clean:
	cargo clean

build:
	cargo build

fmt:
	cargo fmt -- --check

clippy:
	cargo clippy -- --forbid warnings

test:
	cargo test

doc:
	cargo doc
