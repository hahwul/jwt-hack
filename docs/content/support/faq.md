+++
toc = true
title = "FAQ"
weight = 2
+++

## Which algorithms are supported?

HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, and the unsigned `none` algorithm. For JWE, `jwt-hack` handles `dir`, RSA-OAEP, ECDH-ES, and AES key-wrap variants with A128GCM or A256GCM content encryption. The full list is on the [introduction](/get_started/introduction/) page.

## Can `crack` recover an RS256 or ES256 secret?

No, and nothing can. RS/ES/PS/EdDSA tokens are signed with a private key, not a shared secret, so there is no secret to guess. `crack` only works on HMAC tokens (HS256/384/512). If you point it at an asymmetric token it tells you so and stops.

What you *can* do to an RS256 token is test for algorithm confusion, where the server verifies an attacker-supplied HS256 token using the RSA public key as the HMAC secret. See [`payload --target alg_confusion`](/usage/commands/payload/).

## Why does `verify` exit with code 0 even when the token is invalid?

A bad signature is a valid, expected result, not a tool error. `verify` prints `✓ Token is valid.` or `✗ Token is invalid.` and exits 0 in both cases. Parse the stdout line, or use `--json` and read the `valid` field. Exit code 1 is reserved for real failures like an unreadable key file.

## Does `scan` find the secret for me?

It runs a quick weak-secret check against a short built-in list, enough to catch `secret`, `password`, and friends. For a real wordlist, run [`crack`](/usage/commands/crack/) directly, or pass `scan -w <wordlist>`.

## How do I use `jwt-hack` in a script?

Add `--json` to any command for stable machine-readable output. See [Scripting & Automation](/advanced/scripting-automation/) for field names and exit-code behavior.

## Where does `jwt-hack` store its config and cache?

Under `$XDG_CONFIG_HOME/jwt-hack` when `XDG_CONFIG_HOME` is an absolute path, otherwise the platform config directory (`~/.config/jwt-hack` on Linux, `~/Library/Application Support/jwt-hack` on macOS). Downloaded wordlist presets and the shell history file live there too. See [Configuration](/usage/configuration/) and [Environment Variables](/reference/environment-variables/).

## Is this legal to use?

`jwt-hack` is a testing tool. Only run it against tokens and systems you own or have written permission to test. See [SECURITY.md](https://github.com/hahwul/jwt-hack/blob/main/SECURITY.md).

## Something isn't covered here

Open an issue on [GitHub](https://github.com/hahwul/jwt-hack/issues).
