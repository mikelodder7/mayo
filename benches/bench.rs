// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Criterion benchmarks for pq-mayo keygen, sign, and verify.

use criterion::{criterion_group, criterion_main, Criterion};
use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter};
use signature::{Signer, Verifier};

fn bench_keygen<P: MayoParameter>(c: &mut Criterion) {
    c.bench_function(&format!("{}/keygen", P::NAME), |b| {
        let mut rng = rand::rng();
        b.iter(|| KeyPair::<P>::generate(&mut rng).expect("keygen"));
    });
}

fn bench_sign<P: MayoParameter>(c: &mut Criterion) {
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
    let msg = b"benchmark message for signing";

    c.bench_function(&format!("{}/sign", P::NAME), |b| {
        b.iter(|| keypair.signing_key().try_sign(msg).expect("sign"));
    });
}

fn bench_verify<P: MayoParameter>(c: &mut Criterion) {
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
    let msg = b"benchmark message for verify";
    let sig = keypair.signing_key().try_sign(msg).expect("sign");

    c.bench_function(&format!("{}/verify", P::NAME), |b| {
        b.iter(|| keypair.verifying_key().verify(msg, &sig).expect("verify"));
    });
}

fn mayo1_benches(c: &mut Criterion) {
    bench_keygen::<Mayo1>(c);
    bench_sign::<Mayo1>(c);
    bench_verify::<Mayo1>(c);
}

fn mayo2_benches(c: &mut Criterion) {
    bench_keygen::<Mayo2>(c);
    bench_sign::<Mayo2>(c);
    bench_verify::<Mayo2>(c);
}

fn mayo3_benches(c: &mut Criterion) {
    bench_keygen::<Mayo3>(c);
    bench_sign::<Mayo3>(c);
    bench_verify::<Mayo3>(c);
}

fn mayo5_benches(c: &mut Criterion) {
    bench_keygen::<Mayo5>(c);
    bench_sign::<Mayo5>(c);
    bench_verify::<Mayo5>(c);
}

criterion_group!(
    benches,
    mayo1_benches,
    mayo2_benches,
    mayo3_benches,
    mayo5_benches
);
criterion_main!(benches);
