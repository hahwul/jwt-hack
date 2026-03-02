alias ds := docs-serve

default:
    @echo "Listing available tasks..."
    @just --list

docs-serve:
    @echo "Serving the documentation site at http://localhost:3000/ ..."
    hwaro serve -i docs --base-url="http://localhost:3000"

test:
    cargo test
    cargo clippy -- --deny warnings
    cargo clippy --tests -- --deny warnings
    cargo fmt --check
    cargo doc --workspace --all-features --no-deps --document-private-items

fix:
    cargo fmt
    cargo clippy --fix --allow-dirty

build:
    cargo build --release

dev:
    cargo build
