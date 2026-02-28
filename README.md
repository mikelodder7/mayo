# pq-mayo

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/pq-mayo/actions/workflows/mayo.yml/badge.svg)
![MSRV][msrv-image]

A Rust implementation of the [MAYO](https://pqmayo.org/) post-quantum signature scheme, submitted to the NIST PQC standardization process.

## Supported Parameter Sets

| Parameter Set | Security Level | Signature Size | Public Key Size |
|--------------|----------------|----------------|-----------------|
| Mayo1        | 1              | 454 bytes      | 1420 bytes      |
| Mayo2        | 2              | 186 bytes      | 4912 bytes      |
| Mayo3        | 3              | 681 bytes      | 2986 bytes      |
| Mayo5        | 5              | 964 bytes      | 5554 bytes      |

## Usage

### Basic Sign and Verify

```rust
use pq_mayo::{KeyPair, Mayo1};
use signature::{Signer, Verifier};

let mut rng = rand::rng();
let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
let msg = b"hello world";

let sig = keypair.signing_key().try_sign(msg).expect("sign");
keypair.verifying_key().verify(msg, &sig).expect("verify");
```

### Using Different Parameter Sets

```rust
use pq_mayo::{KeyPair, Mayo2, Mayo3, Mayo5};
use signature::{Signer, Verifier};

let mut rng = rand::rng();

// NIST security level 2
let kp2 = KeyPair::<Mayo2>::generate(&mut rng).expect("keygen");
let sig2 = kp2.signing_key().try_sign(b"message").expect("sign");
kp2.verifying_key().verify(b"message", &sig2).expect("verify");

// NIST security level 3
let kp3 = KeyPair::<Mayo3>::generate(&mut rng).expect("keygen");

// NIST security level 5
let kp5 = KeyPair::<Mayo5>::generate(&mut rng).expect("keygen");
```

### Key Serialization

Keys and signatures implement `AsRef<[u8]>` and `TryFrom<&[u8]>` for raw byte serialization:

```rust
use pq_mayo::{KeyPair, Mayo1, SigningKey, VerifyingKey, Signature};
use signature::{Signer, Verifier};

let mut rng = rand::rng();
let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");

// Export keys as raw bytes
let sk_bytes: &[u8] = keypair.signing_key().as_ref();
let vk_bytes: &[u8] = keypair.verifying_key().as_ref();

// Reconstruct keys from bytes
let sk = SigningKey::<Mayo1>::try_from(sk_bytes).expect("valid signing key");
let vk = VerifyingKey::<Mayo1>::try_from(vk_bytes).expect("valid verifying key");

// Sign with reconstructed key, verify with reconstructed key
let sig = sk.try_sign(b"hello").expect("sign");
vk.verify(b"hello", &sig).expect("verify");

// Signatures can also be serialized/deserialized
let sig_bytes: &[u8] = sig.as_ref();
let sig2 = Signature::<Mayo1>::try_from(sig_bytes).expect("valid signature");
```

### Deriving a Verifying Key from a Signing Key

```rust
use pq_mayo::{KeyPair, Mayo1, VerifyingKey};
use signature::{Signer, Verifier};

let mut rng = rand::rng();
let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");

// Derive the verifying (public) key from the signing (secret) key
let vk = VerifyingKey::<Mayo1>::from(keypair.signing_key());
let sig = keypair.signing_key().try_sign(b"test").expect("sign");
vk.verify(b"test", &sig).expect("verify");
```

### Serde Support

Enable the `serde` feature for JSON/binary serialization:

```toml
[dependencies]
pq-mayo = { version = "0.1", features = ["serde"] }
```

```rust,ignore
use pq_mayo::{KeyPair, Mayo1};

let mut rng = rand::rng();
let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");

// Serialize to JSON
let json = serde_json::to_string(&keypair).expect("serialize");
let restored: KeyPair<Mayo1> = serde_json::from_str(&json).expect("deserialize");
```

## Performance

Benchmarked on Apple M1 (aarch64) with `-C target-cpu=native`:

| Operation    | Time       |
|-------------|-----------|
| Mayo1/keygen | 269.19 µs |
| Mayo1/sign   | 698.57 µs |
| Mayo1/verify | 192.85 µs |
| Mayo2/keygen | 331.42 µs |
| Mayo2/sign   | 477.97 µs |
| Mayo2/verify | 87.92 µs  |
| Mayo3/keygen | 765.33 µs |
| Mayo3/sign   | 1.899 ms  |
| Mayo3/verify | 434.75 µs |
| Mayo5/keygen | 1.713 ms  |
| Mayo5/sign   | 4.406 ms  |
| Mayo5/verify | 665.64 µs |

Run your own benchmarks:

```sh
cargo bench
```

## Building and Testing

```sh
# Build
cargo build --release

# Run tests
cargo test

# Clippy
cargo clippy -- -D warnings
```

## Serialization

This crate has been tested against the following `serde` compatible formats:

- [x] serde_bare
- [x] bincode
- [x] postcard
- [x] serde_cbor
- [x] serde_json
- [x] serde_yaml
- [x] toml

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/pq-mayo.svg
[crate-link]: https://crates.io/crates/pq-mayo
[docs-image]: https://docs.rs/pq-mayo/badge.svg
[docs-link]: https://docs.rs/pq-mayo/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/pq-mayo.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.90+-blue.svg
