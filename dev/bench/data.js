window.BENCHMARK_DATA = {
  "lastUpdate": 1785416606925,
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
          "id": "4d7c36609222776e99a639d77856114ee427b672",
          "message": "feat(payload): add claims, JWE, signature-malleability & injection attacks (#259)\n\nExpand the payload generator beyond the header/signature surface it already\ncovered, and turn alg-confusion into a real signed forge.\n\nNew --target types:\n- claims_privesc / claims_exp / claims_confusion: tamper the token body\n  (role/scope/admin escalation, exp/nbf/iat manipulation with type juggling,\n  iss/aud/sub confusion + duplicate-key body). Emitted as alg:none.\n- jwe: JWE header-confusion / DoS probes — PBES2 p2c DoS, alg:dir key\n  confusion, key-management alg downgrades, ECDH-ES invalid-curve epk\n  injection, JWS/JWE type confusion (static probes, no new deps).\n- sig_malleability: ECDSA high-S (s'=n-s) genuine forge + DER-encoded sig +\n  structural probes (zero/truncated/extended signature).\n- kid_injection: NoSQL (incl. operator objects), OS command, SSTI, LDAP,\n  CRLF injection in kid (complements kid_sql).\n- claim_injection: spray XSS/SQLi/SSTI/path/log4j-JNDI/CRLF into string claims.\n\nalg_confusion:\n- new --public-key <PEM|PATH> forges fully signed RS/ES->HS tokens using the\n  key bytes as the HMAC secret, emitting one signed variant per PEM\n  byte-normalization (as-provided / trailing-LF / no-newline) to survive\n  exact-byte mismatches. Threaded through CLI, HTTP server API, and MCP tool.\n\nAll new generators wired into generate_all_payloads, the CLI print path,\nvalid_targets, and --target help. Adds 8 unit tests (incl. OpenSSL-verified\nhigh-S malleability and a verified RS256->HS256 forge). fmt + clippy clean.",
          "timestamp": "2026-07-29T19:54:05+09:00",
          "tree_id": "8cca8104087dac312e570b1b011faa818377f914",
          "url": "https://github.com/hahwul/jwt-hack/commit/4d7c36609222776e99a639d77856114ee427b672"
        },
        "date": 1785322845775,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1176,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 12493,
            "range": "± 67",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1335,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3191,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1484,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 12018,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 26432729,
            "range": "± 2882750",
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
          "id": "4f1c3ccc9a051b87f4cc8f0ccd9e0a9363dd9cb8",
          "message": "fix(jwt): decode ES512 & report real header alg (no HS256 mislabel) (#260)\n\n`decode`/inspection paths surfaced the internal `jsonwebtoken::Algorithm`\nenum, which is lossy:\n\n- ES512 tokens (which `encode` produces via josekit) and tokens with an\n  exotic/attacker-chosen `alg` were rejected with \"Unsupported algorithm\",\n  since jsonwebtoken's enum has no ES512 variant. An inspection tool must\n  never refuse a token merely for its `alg`.\n- `alg:none` tokens were mislabelled `HS256` (the internal sentinel) in the\n  CLI, `--json`, MCP, and REST decode output.\n\nFix:\n- Add `algorithm_from_str` helper and `DecodedToken::alg_str()` (reads the\n  real `alg` from the header).\n- `decode` now falls back to an HS256 sentinel for unrepresentable algs\n  while preserving the true `alg` in the header, so inspection never fails.\n- Display paths report the real header `alg`.\n- Guard the crypto paths: `verify_with_options` returns a clear\n  \"Unsupported algorithm for verification\" error instead of silently\n  HMAC-comparing against the sentinel; `prepare_hs256_verifier` keys off the\n  real header `alg` so a `none`/garbage-alg token is never cracked as HS256.\n\nAdds 5 regression tests.",
          "timestamp": "2026-07-30T21:57:56+09:00",
          "tree_id": "09a6027f1b113d1cb949d9201997089435201401",
          "url": "https://github.com/hahwul/jwt-hack/commit/4f1c3ccc9a051b87f4cc8f0ccd9e0a9363dd9cb8"
        },
        "date": 1785416605998,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 924,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 17592,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1124,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 2706,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1283,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 10262,
            "range": "± 181",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 22814530,
            "range": "± 34837",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}