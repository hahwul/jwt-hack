+++
toc = true
title = "Troubleshooting"
weight = 1
+++

## "Unknown token format: expected 3 parts (JWT) or 5 parts (JWE)"

The input isn't a token. Usually a shell ate part of it, or you passed a file path instead of the token itself. A JWT has three base64url segments split by dots; a JWE has five. Check for stray whitespace or line breaks, and quote the token if it contains characters your shell might expand.

## `crack` says the token can't be cracked

You pointed it at an RS/ES/PS/EdDSA token. Those are signed with a private key, so there is no shared secret to guess. `crack` only applies to HMAC tokens (HS256/384/512). For asymmetric tokens, test algorithm confusion with [`payload`](/usage/commands/payload/) instead.

## `verify` always exits 0

That's intended. An invalid signature is a normal outcome, not a crash. Read the `✓`/`✗` line on stdout, or use `--json` and check the `valid` field. See the [FAQ](/support/faq/#why-does-verify-exit-with-code-0-even-when-the-token-is-invalid).

## `verify` fails on an RS256 token even with the right key

For asymmetric algorithms, `verify` needs the *public* key, and the flag is still `--private-key` (it takes whichever PEM you give it). Passing the private key, or a key in the wrong PEM encoding, produces a false `✗`.

## A preset wordlist won't download

`crack -p` fetches hosted wordlists over HTTPS and caches them under the config directory. On an offline or proxied host the download fails. Supply your own list with `-w <file>` instead, or set `JWT_HACK_WORDLIST_DIR` to a directory that already holds the file.

## Brute force runs forever

The keyspace grows exponentially with `--max`. Keep `--max` small, narrow the character set with `--preset` or `--chars`, and add `--power` to use every core. If you have any hint about the secret's shape, a targeted `--pattern` is far faster than blind brute force.

## Colors or symbols look wrong in captured output

`jwt-hack` disables color when output isn't a terminal or when `NO_COLOR` is set, so piped and logged output stays plain. The severity markers (`✓ ▲ ◆ ■`) are still printed as text. For fully structured output, use `--json`.

## Still stuck

Run `jwt-hack <command> --help` to confirm the exact flags, then open an issue on [GitHub](https://github.com/hahwul/jwt-hack/issues) with the command you ran and the output you got.
