+++
toc = true
title = "Examples"
weight = 4
+++

Copy-paste recipes for the things people reach for most. For a guided first run, start with the [quick start](/get_started/quickstart/); for every flag, see the [command pages](/usage/commands/).

## Read and sign

```bash
# Decode a token (no secret needed)
jwt-hack decode "$TOKEN"

# Sign with an HMAC secret
jwt-hack encode '{"sub":"1234","name":"John Doe","admin":true}' --secret=mysecret

# Sign with an RSA key
jwt-hack encode '{"sub":"1234","role":"admin"}' --private-key=private.pem --algorithm=RS256

# Verify a signature, and reject if expired
jwt-hack verify "$TOKEN" --secret=mysecret --validate-exp
```

## Crack a weak secret

```bash
# Dictionary attack with your own wordlist
jwt-hack crack -w rockyou.txt "$TOKEN"

# No wordlist handy? Pull a known-secrets list by number
jwt-hack crack -p 3 "$TOKEN"

# Brute force a short secret across every core
jwt-hack crack -m brute "$TOKEN" --preset aZ19 --max=4 --power
```

## Generate attack tokens

```bash
# Everything, piped to a file for an Intruder-style runner
jwt-hack payload "$TOKEN" --target=all > payloads.txt

# Just the none-algorithm variants
jwt-hack payload "$TOKEN" --target=none

# Algorithm confusion, forged and signed with the server's public key
jwt-hack payload "$RSA_TOKEN" --target=alg_confusion --public-key=./server-pub.pem
```

See [payload](/usage/commands/payload/) for the full target list.

## A full pass on one token

```bash
# 1. See what it is
jwt-hack decode "$TOKEN"

# 2. Triage: weaknesses, weak secret, suggested payloads
jwt-hack scan "$TOKEN"

# 3. If scan flags a weak secret, crack it for real
jwt-hack crack -w rockyou.txt "$TOKEN"

# 4. If the secret holds, probe parsing and key handling
jwt-hack payload "$TOKEN" --target=none,alg_confusion,kid_sql
```

## Custom headers

Each header is its own `key=value` flag, not a JSON object. This is how you set a `kid`:

```bash
jwt-hack encode '{"sub":"1234"}' \
  --secret=test \
  --header kid=key-123 \
  --header x5u=https://example.com/certs
```

## Compressed tokens

`encode --compress` adds `"zip":"DEF"`; decode and crack both unpack it for you, no extra flag.

```bash
jwt-hack encode '{"data":"...long payload..."}' --secret=test --compress
jwt-hack decode "$COMPRESSED_TOKEN"
jwt-hack crack -w wordlist.txt "$COMPRESSED_TOKEN"
```

## With other tools

```bash
# Sign a token and send it in a request
TOKEN=$(jwt-hack encode '{"sub":"user123"}' --secret=mysecret)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data

# Pull one claim out of a decode
jwt-hack --json decode "$TOKEN" | jq '.payload.sub'
```

For wiring `jwt-hack` into scripts and CI with `--json`, see [Scripting & Automation](/advanced/scripting-automation/).
