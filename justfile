alias b := build
alias d := dev
alias ds := docs-serve
alias t := test
alias vc := version-check
alias vu := version-update

# List available tasks.
default:
    @just --list

# Build release binary.
[group('build')]
build:
    cargo build --release

# Build debug binary.
[group('build')]
dev:
    cargo build

# Serve docs site locally.
[group('documents')]
docs-serve:
    hwaro serve -i docs --base-url="http://localhost:3000"

# Install docs dependencies (macOS).
[group('documents')]
docs-dependencies:
    brew install hahwul/hwaro/hwaro

# Format and auto-fix lints.
[group('development')]
fix:
    cargo fmt
    cargo clippy --fix --allow-dirty

# Report jwt-hack version across Cargo.toml, Cargo.lock, snap, aur, docs, README.
[group('release')]
version-check:
    crystal run scripts/version_check.cr

# Bump jwt-hack version in lockstep across all version-bearing files (incl. docs/README).
[group('release')]
version-update:
    crystal run scripts/version_update.cr

# Run tests, lints, format and doc checks.
[group('test')]
test:
    cargo test
    cargo clippy -- --deny warnings
    cargo clippy --tests -- --deny warnings
    cargo fmt --check
    cargo doc --workspace --all-features --no-deps --document-private-items

# Run criterion performance benchmarks.
[group('test')]
bench:
    cargo bench

# Run a cargo-fuzz target (requires nightly + cargo-fuzz). Usage: just fuzz jwt_decode
[group('test')]
fuzz target="jwt_decode" time="60":
    cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}
