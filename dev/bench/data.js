window.BENCHMARK_DATA = {
  "lastUpdate": 1788309497571,
  "repoUrl": "https://github.com/hahwul/jwt-hack",
  "entries": {
    "jwt-hack benchmarks": [
      {
        "commit": {
          "author": {
            "email": "hahwul@gmail.com",
            "name": "hahwul",
            "username": "hahwul"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "92aa09c0d9b77f62f78d0f143381c0b871746049",
          "message": "fix(crack): harden brute-force keyspace math against panics (#288)\n\n* fix(crack): harden brute-force keyspace math against panics\n\nThree crash-prone spots in the brute-force helpers:\n\n- `generate_bruteforce_payloads` computed the progress denominator with a\n  plain `pow`/`sum`, which overflows `usize` for a large charset or\n  `max_length` — panicking in debug/test builds and silently wrapping in\n  release. Reuse the saturating `estimate_combinations` helper and saturate\n  the u64->usize conversion instead of truncating.\n- `write_candidate_bytes` divided by `charset_size` without guarding the\n  empty-charset case (`n % 0` panic) and indexed a fixed\n  `[_; MAX_BRUTE_LENGTH]` buffer with an unchecked `length` (out-of-bounds\n  panic even in release). Add early-return guards for both.\n\nAdd a regression test for the empty-charset path.\n\n* style: rustfmt one-line total_combinations expression",
          "timestamp": "2026-08-30T16:37:15+09:00",
          "tree_id": "36766973bbffe2ca86ae12c9af74a520ca1b8ae5",
          "url": "https://github.com/hahwul/jwt-hack/commit/92aa09c0d9b77f62f78d0f143381c0b871746049"
        },
        "date": 1788075837030,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1187,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 12312,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1345,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3293,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1497,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 12100,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 26720379,
            "range": "± 212449",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "hahwul@gmail.com",
            "name": "hahwul",
            "username": "hahwul"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "478ace9e6c7a9e81c6d8cf9a44e79ebede6d213d",
          "message": "fix(crack): reject non-HMAC/none tokens instead of silent not-found (#289)\n\nDictionary and brute-force cracking search for a shared HMAC secret,\nwhich only exists for HS256/HS384/HS512. Feeding the crack subcommand an\nRS*/ES*/PS*/EdDSA or none-alg token previously ran the ENTIRE keyspace\n(or wordlist) and then reported \"Secret not found\" — implying the secret\nwas merely out of range, when in fact no candidate secret can ever verify\nsuch a token (it is signed with a private key, or carries no signature).\n\nReject those tokens up front with a clear message via a new\nensure_secret_crackable() guard called at the top of crack_dictionary and\ncrack_bruteforce. JWE tokens are exempt (cracked by direct key\ndecryption, not signature verification). This mirrors how the scan\nsubcommand's weak-secret check already skips non-HS algorithms.\n\nIn --json mode the guard surfaces as the standard structured error\nresponse with exit code 1, instead of a misleading found:false report.\n\nAdds unit tests covering: HMAC algs allowed (incl. mixed case),\nRS256/ES256/ES512/PS256/EdDSA/none rejected, JWE exemption, and that both\ncrack_bruteforce and crack_dictionary return Err for a non-HMAC token.",
          "timestamp": "2026-09-02T09:03:43+09:00",
          "tree_id": "4c381f9760a85c205812d82fe34769126d4a7be2",
          "url": "https://github.com/hahwul/jwt-hack/commit/478ace9e6c7a9e81c6d8cf9a44e79ebede6d213d"
        },
        "date": 1788307817172,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1161,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 22654,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1477,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3469,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1645,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 13173,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 29249905,
            "range": "± 28078",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "hahwul@gmail.com",
            "name": "hahwul",
            "username": "hahwul"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4556f096c1f48aa903d598026e83a688226839fa",
          "message": "fix(interfaces): harden config dir, server bind, and shell title bar (#290)\n\nThree defects in the interfaces layer:\n\n* config: an empty `XDG_CONFIG_HOME=\"\"` (set-but-empty) resolved the config\n  directory to a CWD-relative `jwt-hack` via `PathBuf::from(\"\").join(...)`,\n  violating the XDG Base Directory spec (which mandates absolute paths and\n  treats an empty value as unset). Config, shell history, and `Config::load`\n  would then read/write a directory relative to wherever the tool was launched\n  — and `Config::load` could silently pick up an attacker-planted\n  `./jwt-hack/config.toml`. Now only absolute `XDG_CONFIG_HOME` values are\n  honored; empty/relative ones fall back to the platform default. Logic split\n  into a pure `resolve_config_dir` helper so it is testable without mutating the\n  process-global environment.\n\n* server: `execute`/`execute_with_api_key` called `.expect()` on the TCP bind\n  and on `axum::serve`, so a routine \"address already in use\" turned into a\n  Rust panic + backtrace note (aborting under `panic = \"abort\"`). Bind/serve\n  now report a clean error line and exit non-zero via a shared `serve_app`; the\n  bind is factored into a testable `bind_listener`.\n\n* shell UI: the title-bar rule width was computed from UTF-8 byte length, but\n  the right-side indicators contain 3-byte/1-column glyphs (`│`, `●`, `○`), so\n  the rule fell ~6 columns short and left a gap before the indicators. Width is\n  now measured in visible columns via `title_rule_width`.\n\nAdds unit tests for each fix.",
          "timestamp": "2026-09-02T09:05:08+09:00",
          "tree_id": "711681da90e7caa6317373fab6965eb8c65f1010",
          "url": "https://github.com/hahwul/jwt-hack/commit/4556f096c1f48aa903d598026e83a688226839fa"
        },
        "date": 1788307903722,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1175,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 12858,
            "range": "± 188",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1332,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3236,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1504,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 12090,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 26691623,
            "range": "± 48668",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "hahwul@gmail.com",
            "name": "hahwul",
            "username": "hahwul"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "edb86ecf3abca6e8e95e5614156ba5ae245bee03",
          "message": "fix(jwt): correct verification of compressed tokens and key/alg handling (#292)\n\nFive defects found by running the CLI against adversarial and round-trip\ninputs in the core JWT engine.\n\n1. verify: a correctly signed `zip:\"DEF\"` token was reported invalid for\n   every algorithm except HS256. All non-HS256 paths hand the whole token\n   to `jsonwebtoken::decode`, which deserializes the payload segment as\n   JSON claims; a DEFLATE payload is not JSON, so verification always\n   failed and collapsed into a plain \"Token is invalid\". HS256 fared no\n   better once `--validate-exp` was requested — the time check re-parsed\n   the compressed payload and errored with\n   `Json(Error(\"expected value\", line: 1, column: 1))`, so an expired\n   compressed token was never reported as expired. Compressed tokens now\n   verify the signature over the signing input via\n   `jsonwebtoken::crypto::verify` and check `exp`/`nbf` against the\n   already-inflated claims from `decode`. The same shared time-claim check\n   replaces the hand-rolled one in the ES512 path, which silently skipped\n   `exp`/`nbf` for a compressed token.\n\n2. encode: `--compress` wrote the raw `--algorithm` string into the\n   header, so `--algorithm hs256 --compress` emitted `\"alg\":\"hs256\"` —\n   a value conforming JWT libraries reject, since `alg` names are\n   case-sensitive (RFC 7515 4.1.1). The uncompressed encoder already\n   normalized the same input to `HS256`. The compressed header now carries\n   the canonical name, and `none` keeps its lowercase spelling.\n\n3. verify: `--private-key` is named and documented as taking the private\n   key (README shows exactly that), but a signature can only be checked\n   against the public key. RSA silently returned the wrong answer — the\n   PKCS#1 reader treats an `RSA PRIVATE KEY` blob as a public key, so a\n   validly signed token was reported invalid — while EC/EdDSA failed with\n   an opaque `InvalidKeyFormat` and ES512 with \"Inappropriate algorithm\".\n   A private-key PEM is now converted to its public half; an unrelated key\n   pair is still rejected.\n\n4. encode/verify: a passphrase-protected PEM made OpenSSL fall back to its\n   default UI and block on an \"Enter PEM pass phrase:\" prompt read from\n   the terminal, hanging non-interactive runs. Encrypted PEMs are rejected\n   up front with actionable guidance, and key parsing always supplies a\n   passphrase so the terminal UI is never reached.\n\n5. verify: a JWE (5-segment) token surfaced as\n   \"EOF while parsing a value at line 1 column 0\" because its encrypted-key\n   segment was parsed as a JSON payload. It now reports what the token\n   actually is.\n\nAlso replaces a misleading \"HMAC algorithms require a secret key\" error\nraised when a secret was supplied but compression was requested with a\nnon-HMAC algorithm.\n\nJSON output keys and structure are unchanged.",
          "timestamp": "2026-09-02T09:15:26+09:00",
          "tree_id": "bb1684da03a643f6cc3c2f6a1286de4a8d00087f",
          "url": "https://github.com/hahwul/jwt-hack/commit/edb86ecf3abca6e8e95e5614156ba5ae245bee03"
        },
        "date": 1788308532032,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1194,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 12740,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1368,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3294,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1516,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 11964,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 26337350,
            "range": "± 592127",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "hahwul@gmail.com",
            "name": "hahwul",
            "username": "hahwul"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8a31c6297ad905728d15e36c639c73ac5c671ae0",
          "message": "fix(payload): build full jku/x5u URL in basic payload instead of bare domain (#293)\n\nThe basic jku/x5u payload emitted the raw --jwk-attack value verbatim\n(e.g. `jku: \"evil.com\"`), which is not a valid absolute URI and silently\nignored --jwk-protocol. A server resolving the header would never fetch\nthe attacker's endpoint, so the primary (and most important) URL payload\nwas effectively non-functional, while every bypass variant and the SSRF\nprobes correctly used a full `{protocol}://…` URL.\n\nPrepend the configured scheme so the basic payload is a fetchable URL\nthat honours --jwk-protocol, matching the bypass and SSRF variants. A\nvalue that already carries a scheme is passed through verbatim to avoid\nproducing a double scheme.\n\nUpdates the affected unit tests and adds a regression test asserting the\nscheme is applied (and not duplicated for pre-schemed inputs).",
          "timestamp": "2026-09-02T09:32:50+09:00",
          "tree_id": "a38986864a468c483a89e58f3ff2e98012fe86a0",
          "url": "https://github.com/hahwul/jwt-hack/commit/8a31c6297ad905728d15e36c639c73ac5c671ae0"
        },
        "date": 1788309496215,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 914,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 17708,
            "range": "± 182",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1136,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 2750,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1284,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 10263,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 22847248,
            "range": "± 46069",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}