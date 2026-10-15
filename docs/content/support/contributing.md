+++
toc = true
title = "Contributing"
weight = 4
+++

Patches, bug reports, and new attack ideas are all welcome. This page is the short version; the [full CONTRIBUTING.md](https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md) in the repo has the rest.

## Set up

You need Rust and Cargo (latest stable). [Just](https://github.com/casey/just) is optional but it wraps the common tasks:

```bash
cargo install just

git clone https://github.com/YOUR-USERNAME/jwt-hack.git
cd jwt-hack
git checkout -b fix-the-thing
```

## Build and test

```bash
just dev    # debug build
just test   # cargo test + clippy + fmt --check + doc
just fix    # format and auto-fix lints
```

`just test` runs everything CI runs, so if it passes locally the pull request should too. To run only part of it:

```bash
cargo test                       # unit tests
cargo test --test e2e            # end-to-end tests
cargo test --test interop        # cross-library interop tests
cargo clippy -- --deny warnings  # lint
cargo fmt --check                # format check
```

## Before you open a PR

- `just test` is clean.
- New behavior has tests covering it.
- Docs are updated if a flag or command changed.
- Commit messages say what changed in the present tense, and reference an issue when there is one (for example `Fix #123: reject empty kid`).

Then push your branch and open the pull request against `main`. If you are adding a JWT attack that `payload` or `scan` does not cover yet, say so in the description so it is easy to review.
