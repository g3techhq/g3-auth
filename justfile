set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

setup:
    lefthook install

format:
    cargo fmt --all
    cargo fmt --manifest-path macros/Cargo.toml

format-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path macros/Cargo.toml -- --check

check:
    cargo check
    cargo check --features server
    cargo check --features "server google"
    cargo check --features "mobile desktop"
    cargo check --target wasm32-unknown-unknown
    cargo check --target wasm32-unknown-unknown --features google
    cargo check --manifest-path macros/Cargo.toml

lint:
    cargo clippy --all-targets --no-deps --features server
    cargo clippy --manifest-path macros/Cargo.toml --all-targets --no-deps

lint-strict:
    cargo clippy --all-targets --no-deps --features "server google" -- -D warnings
    cargo clippy --no-deps --target wasm32-unknown-unknown --features google -- -D warnings
    cargo clippy --manifest-path macros/Cargo.toml --all-targets --no-deps -- -D warnings

test:
    cargo nextest run --features "server google"
    cargo nextest run --manifest-path macros/Cargo.toml --no-tests pass
    cargo test --doc --features "server google"
    cargo test --doc --manifest-path macros/Cargo.toml

spell:
    typos

security:
    cargo deny check

pre-push: format-check check lint-strict test spell

quality: pre-push

package-check:
    cargo package --allow-dirty --manifest-path macros/Cargo.toml
    cargo package --allow-dirty --list

ci: quality security package-check

package:
    cargo package --manifest-path macros/Cargo.toml
    cargo package

