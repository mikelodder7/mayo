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
| Mayo1/keygen | 404.19 µs |
| Mayo1/sign   | 887.96 µs |
| Mayo1/verify | 324.92 µs |
| Mayo2/keygen | 453.25 µs |
| Mayo2/sign   | 629.77 µs |
| Mayo2/verify | 201.88 µs |
| Mayo3/keygen | 1.000 ms  |
| Mayo3/sign   | 2.207 ms  |
| Mayo3/verify | 676.01 µs |
| Mayo5/keygen | 2.220 ms  |
| Mayo5/sign   | 5.052 ms  |
| Mayo5/verify | 1.218 ms  |

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
