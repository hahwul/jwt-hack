//! Criterion performance benchmarks for jwt-hack's core operations.
//!
//! Covers the operations called out in issue #184: encode, decode, verify, and
//! cracking (dictionary + brute force). Run with `cargo bench`.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jwt_hack::crack::brute;
use jwt_hack::jwt::{self, EncodeOptions, KeyData};
use serde_json::json;

fn sample_claims() -> serde_json::Value {
    json!({
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1_516_239_022,
        "role": "admin",
        "scope": "read write"
    })
}

fn bench_encode(c: &mut Criterion) {
    let claims = sample_claims();
    c.bench_function("encode_hs256", |b| {
        b.iter(|| jwt::encode(black_box(&claims), black_box("secret"), "HS256").unwrap())
    });

    let claims_c = sample_claims();
    c.bench_function("encode_hs256_compressed", |b| {
        let options = EncodeOptions {
            algorithm: "HS256",
            key_data: KeyData::Secret("secret"),
            header_params: None,
            compress_payload: true,
        };
        b.iter(|| jwt::encode_with_options(black_box(&claims_c), &options).unwrap())
    });
}

fn bench_decode(c: &mut Criterion) {
    let token = jwt::encode(&sample_claims(), "secret", "HS256").unwrap();
    c.bench_function("decode", |b| {
        b.iter(|| jwt::decode(black_box(&token)).unwrap())
    });
}

fn bench_verify(c: &mut Criterion) {
    let token = jwt::encode(&sample_claims(), "secret", "HS256").unwrap();

    c.bench_function("verify_hs256", |b| {
        b.iter(|| jwt::verify(black_box(&token), black_box("secret")).unwrap())
    });

    // The reusable fast-path verifier used inside the crack hot loop.
    let verifier = jwt::prepare_hs256_verifier(&token).unwrap();
    c.bench_function("verify_hs256_fastpath", |b| {
        b.iter(|| black_box(verifier.verify(black_box(b"secret"))))
    });
}

fn bench_crack_dict(c: &mut Criterion) {
    let token = jwt::encode(&sample_claims(), "letmein", "HS256").unwrap();
    let wordlist = [
        "password", "123456", "admin", "root", "qwerty", "secret", "dragon", "letmein",
    ];
    let verifier = jwt::prepare_hs256_verifier(&token).unwrap();

    c.bench_function("crack_dict_8_words", |b| {
        b.iter(|| {
            black_box(
                wordlist
                    .iter()
                    .find(|w| verifier.verify(w.as_bytes()))
                    .copied(),
            )
        })
    });
}

fn bench_crack_brute(c: &mut Criterion) {
    // Worst-case: the secret is the last 3-char lowercase candidate ("zzz"), so
    // the loop enumerates the full 26^3 keyspace before finding it.
    let token = jwt::encode(&sample_claims(), "zzz", "HS256").unwrap();
    let verifier = jwt::prepare_hs256_verifier(&token).unwrap();
    let char_bytes = brute::charset_bytes("abcdefghijklmnopqrstuvwxyz");
    let length = 3usize;
    let total = (char_bytes.len() as u64).pow(length as u32);

    c.bench_function("crack_brute_len3_lower", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(length);
            let mut found = None;
            for idx in 0..total {
                brute::write_candidate_bytes(idx, &char_bytes, length, &mut buf);
                if verifier.verify(&buf) {
                    found = Some(idx);
                    break;
                }
            }
            black_box(found)
        })
    });
}

criterion_group! {
    name = benches;
    // Keep CI wall-clock bounded while still statistically meaningful.
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3));
    targets =
        bench_encode,
        bench_decode,
        bench_verify,
        bench_crack_dict,
        bench_crack_brute
}
criterion_main!(benches);
