+++
toc = true
title = "verify"
weight = 3
+++

Check whether a token's signature holds against a given secret or key, and optionally whether it has expired.

## Usage

```bash
jwt-hack verify <TOKEN> [OPTIONS]
```

```bash
jwt-hack verify "$TOKEN" --secret=test
```

```text
✓ Token is valid.
```

A bad secret or key prints `✗ Token is invalid.`

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--secret <SECRET>` | from config | HMAC key for HS256/384/512. |
| `--private-key <PRIVATE_KEY>` | from config | Public key in PEM for RSA/ECDSA/EdDSA verification. The flag is named `private-key` but for verify you pass the public key. |
| `--validate-exp` | off | Also check the `exp` claim and fail if the token has expired. |

Despite the name, asymmetric verification wants the public key (X.509 `BEGIN PUBLIC KEY` or PKCS#1 `BEGIN RSA PUBLIC KEY`):

```bash
jwt-hack verify "$RSA_TOKEN" --private-key=public.pem
```

## Expiration

By default verify only looks at the signature, not the clock. Add `--validate-exp` to reject expired tokens:

```bash
jwt-hack verify "$TOKEN" --secret=mysecret --validate-exp
```

## Scripting

Verify always exits `0`, even on an invalid signature: the result is in the output, not the exit code. For a script, use `--json` and read the `valid` field.

```bash
jwt-hack --json verify "$TOKEN" --secret=test
# => {"success":true,"valid":true,"validate_exp":false}
```

```bash
if [ "$(jwt-hack --json verify "$TOKEN" --secret="$SECRET" | jq -r .valid)" = "true" ]; then
  echo "valid"
fi
```

## Testing for weaknesses

Verify is a convenient oracle during testing. To check algorithm confusion, pass the server's public key bytes as the HMAC secret and see if an RS/ES token verifies as HS:

```bash
jwt-hack verify "$RSA_TOKEN" --secret="$(cat server-public.pem)"
```

If that works, the server is confusing symmetric and asymmetric verification. [payload](/usage/commands/payload/) with `--target alg_confusion --public-key` forges the full token for you. To hunt for the signing secret of an HS token instead, use [crack](/usage/commands/crack/).
