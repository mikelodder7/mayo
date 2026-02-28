# pq-mayo

A Rust implementation of the [MAYO](https://pqmayo.org/) post-quantum signature scheme, submitted to the NIST PQC standardization process.

## Supported Parameter Sets

| Parameter Set | Security Level | Signature Size | Public Key Size |
|--------------|----------------|----------------|-----------------|
| Mayo1        | 1              | 454 bytes      | 1420 bytes      |
| Mayo2        | 2              | 186 bytes      | 4912 bytes      |
| Mayo3        | 3              | 681 bytes      | 2986 bytes      |
| Mayo5        | 5              | 964 bytes      | 5554 bytes      |

## Usage

```rust
use pq_mayo::{KeyPair, Mayo1};
use signature::{Signer, Verifier};

let mut rng = rand::rng();
let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
let msg = b"hello world";

let sig = keypair.signing_key().try_sign(msg).expect("sign");
keypair.verifying_key().verify(msg, &sig).expect("verify");
```

## Performance

Benchmarked on Apple M3 Max (aarch64) with `-C target-cpu=native`:

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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
