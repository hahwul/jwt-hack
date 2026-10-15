window.BENCHMARK_DATA = {
  "lastUpdate": 1792074670355,
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
          "id": "e9209db0133554e7a62d76ac5b325a0095100c7e",
          "message": "fix(server,jwt): harden REST handlers and encode header handling (#326)\n\n- server: run /encode and /payload heavy work (asymmetric signing, RSA/EC\n  keygen, DEFLATE) on a blocking thread under the shared concurrency limiter,\n  so a burst of requests can no longer pin Tokio workers and stall the runtime\n  (request DoS). Rename CRACK_LIMITER -> HEAVY_LIMITER to reflect its scope.\n- server: /scan now honors the request's max_crack_attempts bound; it was\n  ignored, letting a client force the whole (up to 64 MiB) wordlist to be tried.\n- server: apply the CORS layer outermost so a CORS preflight (OPTIONS, which\n  carries no X-API-KEY) is answered instead of being rejected 401 by the API-key\n  middleware when --api-key is set. Real requests still pass through auth.\n- jwt: ignore a `--header alg=...` override on the `none` and compressed encode\n  paths, matching the signed path, so the header can no longer advertise an\n  algorithm that disagrees with how the token is actually signed/unsigned.\n\nAdd unit tests for the max_crack_attempts bound and the alg-override guard.",
          "timestamp": "2026-10-15T23:25:05+09:00",
          "tree_id": "30f908a784fc389e3b51efa9dd8cd12f7da06af1",
          "url": "https://github.com/hahwul/jwt-hack/commit/e9209db0133554e7a62d76ac5b325a0095100c7e"
        },
        "date": 1792074669721,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 1250,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 12091,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 1418,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 3212,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1475,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 11896,
            "range": "± 77",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 26244527,
            "range": "± 32887",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}