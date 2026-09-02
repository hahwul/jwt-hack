window.BENCHMARK_DATA = {
  "lastUpdate": 1788307818759,
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
      }
    ]
  }
}