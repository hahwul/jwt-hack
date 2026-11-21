window.BENCHMARK_DATA = {
  "lastUpdate": 1795268016258,
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
          "id": "300e1eced50de450eaee7095a06d62df855b5bdf",
          "message": "fix(server): report JSON startup after binding (#359)",
          "timestamp": "2026-11-21T22:28:03+09:00",
          "tree_id": "630b05b2e2d5f594b8abda3b1cfaa16965015458",
          "url": "https://github.com/hahwul/jwt-hack/commit/300e1eced50de450eaee7095a06d62df855b5bdf"
        },
        "date": 1795268015632,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 604,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 5724,
            "range": "± 125",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 684,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 1354,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 969,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 7538,
            "range": "± 127",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 16423162,
            "range": "± 469020",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}