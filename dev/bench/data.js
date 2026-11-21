window.BENCHMARK_DATA = {
  "lastUpdate": 1795268209703,
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
          "id": "939cb6959fd714abd7c9e4fa05caf4f25fcc7951",
          "message": "fix(decode): preserve claims that overlap timestamp annotations (#360)",
          "timestamp": "2026-11-21T22:31:38+09:00",
          "tree_id": "da977ddfa7eff1347a820e6403542cb4381a1e1c",
          "url": "https://github.com/hahwul/jwt-hack/commit/939cb6959fd714abd7c9e4fa05caf4f25fcc7951"
        },
        "date": 1795268209158,
        "tool": "cargo",
        "benches": [
          {
            "name": "encode_hs256",
            "value": 808,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "encode_hs256_compressed",
            "value": 17173,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "decode",
            "value": 951,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256",
            "value": 1775,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "verify_hs256_fastpath",
            "value": 1285,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "crack_dict_8_words",
            "value": 10349,
            "range": "± 75",
            "unit": "ns/iter"
          },
          {
            "name": "crack_brute_len3_lower",
            "value": 22938010,
            "range": "± 93009",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}