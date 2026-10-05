+++
toc = true
title = "crack"
weight = 4
+++

Recover the HMAC secret behind an HS256/384/512 token, either by running a wordlist or by brute-forcing character combinations. Work runs in parallel across threads.

Reach for dictionary mode first: real secrets are almost always words, leaked passwords, or app names, and a good wordlist finds them in seconds. Brute force only pays off for short, random secrets (4-5 chars), past that the search space makes it impractical.

## Usage

```bash
jwt-hack crack [OPTIONS] <TOKEN>
```

## Dictionary attack (default)

```bash
jwt-hack crack -w samples/wordlist.txt "$TOKEN"
```

```text
✓ Secret found

  Secret        test
  Time          0 seconds (24428.12 keys/sec)
  Token         eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

No hit prints the count tried, elapsed time, and throughput:

```text
✗ Secret not found (19 keys in 0 seconds, 16119.90 keys/sec)
```

### Preset wordlists

Instead of sourcing a file, pull one by number. It downloads once into the config dir (`<config>/jwt-hack/wordlists/`) with a checksum sidecar, and later runs reuse the cached copy when the hash matches.

```bash
jwt-hack crack -p 3 "$TOKEN"     # jwt-secrets
```

| Preset | Name | Source |
|--------|------|--------|
| `1` | raft-medium-words | SecLists, medium web-content list |
| `2` | raft-large-words | SecLists, large web-content list |
| `3` | jwt-secrets | Wallarm jwt-secrets, common JWT keys |

## Brute force

```bash
jwt-hack crack -m brute "$TOKEN" --max=4
```

The default charset is lowercase plus digits (`abcdefghijklmnopqrstuvwxyz0123456789`), lengths 1 to 4. Override with `--chars`, or pick a preset:

| Preset | Characters |
|--------|------------|
| `az` | a-z |
| `AZ` | A-Z |
| `aZ` | a-z, A-Z |
| `19` | 0-9 |
| `aZ19` | a-z, A-Z, 0-9 |
| `ascii` | all printable ASCII |

```bash
jwt-hack crack -m brute "$TOKEN" --preset=aZ19 --min=1 --max=5 --power
```

## Targeting a header field

Instead of the signing secret, you can brute-force a value for a named header field (such as `kid`) and sign each candidate, which is useful against `kid`-based path traversal or predictable key lookups. `--pattern` wraps each candidate, with `{}` as the placeholder.

```bash
jwt-hack crack "$TOKEN" --target-field kid --pattern "../../keys/{}" -w names.txt
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --mode <MODE>` | `dict` | `dict` or `brute`. |
| `-w, --wordlist <WORDLIST>` | from config | Wordlist file for dictionary mode, one candidate per line. |
| `-p, --wordlist-preset <ID>` | none | Download and use preset `1`, `2`, or `3`. |
| `--chars <CHARS>` | `a-z0-9` | Character set for brute force. |
| `--preset <PRESET>` | none | Named charset: `az`, `AZ`, `aZ`, `19`, `aZ19`, `ascii`. |
| `--min <MIN>` | `1` | Minimum candidate length (brute). |
| `--max <MAX>` | `4` | Maximum candidate length (brute). |
| `-c, --concurrency <N>` | `20` | Worker threads. |
| `--power` | off | Use all CPU cores, overriding `--concurrency`. |
| `--target-field <FIELD>` | none | Brute-force a header field value instead of the secret. |
| `--pattern <TEMPLATE>` | none | Template for targeted values, `{}` is the placeholder. |
| `--verbose` | off | Log each candidate as it is tested. |

A progress bar shows by default; `--verbose` adds a line per candidate. Compressed (`zip:DEF`) tokens are decompressed during the check automatically.

## Notes

- Only HMAC tokens have a secret to crack. For RS/ES/PS/EdDSA, see algorithm-confusion testing in [verify](/usage/commands/verify/) and [payload](/usage/commands/payload/).
- Crack tokens you own or are authorized to test.
