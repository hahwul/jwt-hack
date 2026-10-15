+++
toc = true
title = "Performance"
weight = 1
+++

Only `crack` is heavy enough to tune. Everything else runs in milliseconds. This page covers the knobs that actually move cracking speed, and the fact that for most tokens a better wordlist beats any of them.

## Use more cores

Cracking runs in parallel. By default it uses 20 worker threads; `--power` uses every core on the machine.

```bash
# All cores
jwt-hack crack -w wordlist.txt <TOKEN> --power

# A fixed number of threads
jwt-hack crack -w wordlist.txt <TOKEN> -c 16
```

`--power` overrides `-c`. On a shared box, pin a number with `-c` so you leave headroom for everything else.

## Shrink the brute-force keyspace

Brute force grows exponentially with length, so the search space, not the CPU, is what kills a run. Keep the secret's shape in mind and cut the space down before you cut threads:

```bash
# Lowercase + digits only, up to 4 chars
jwt-hack crack -m brute <TOKEN> --preset aZ19 --max=4 --power
```

- `--max` is the single biggest lever. Every extra character multiplies the work.
- `--preset` or `--chars` narrows the alphabet. Do not throw `ascii` at it unless you have to.
- `--pattern` with `--target-field` beats blind brute force whenever you know the format (for example `../../keys/{}` for a `kid` path).

Past 5 or 6 random characters, brute force stops being practical. Switch to a wordlist.

## Prefer a good wordlist

Real secrets are almost always words, leaked passwords, or app names, so dictionary mode finds them far faster than brute force ever will.

```bash
# A targeted list first, a big one only if it misses
jwt-hack crack -w top-secrets.txt <TOKEN>
jwt-hack crack -w rockyou.txt <TOKEN>
```

The preset lists (`-p 1|2|3`) download once and cache under the config dir, so repeat runs skip the fetch. See [crack](/usage/commands/crack/) for the preset table.

## Build

The release build is the one you want for long runs; the debug build is noticeably slower. Install from crates.io (`cargo install jwt-hack`) or use a packaged release and you already have an optimized binary. If you build locally, use `--release`:

```bash
cargo build --release
./target/release/jwt-hack crack -w wordlist.txt <TOKEN>
```
