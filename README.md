<h1 align="center">ark-groth16</h1>

<p align="center">
    <img src="https://github.com/arkworks-rs/groth16/workflows/CI/badge.svg?branch=master">
    <a href="https://github.com/arkworks-rs/groth16/blob/master/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
    <a href="https://github.com/arkworks-rs/groth16/blob/master/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <a href="https://deps.rs/repo/github/arkworks-rs/groth16"><img src="https://deps.rs/repo/github/arkworks-rs/groth16/status.svg"></a>
</p>

The arkworks ecosystem consist of Rust libraries for designing and working with **zero knowledge succinct non-interactive arguments (zkSNARKs)**. This repository contains an efficient implementation of the zkSNARK of [[Groth16]](https://eprint.iacr.org/2016/260).

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:

```bash
rustup install stable
```

After that, use `cargo`, the standard Rust build tool, to build the library:

```bash
git clone https://github.com/arkworks-rs/groth16.git
cd groth16
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:

```bash
cargo test
```

## Distributed and Checkpointed Proof Generation

This library supports distributed and checkpointed versions of Groth16 proof generation, enabling efficient computation across multiple machines and resumable proof generation.

### Distributed Proof Generation

The distributed version splits the Multi-Scalar Multiplication (MSM) computations across multiple participants:

```rust
use ark_groth16::{Groth16, Either};
use ark_bn254::Bn254;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::thread_rng;

type MyGroth16 = Groth16<Bn254>;

// For participant i out of total participants
let participant_id = 0; // 0 for coordinator, 1..total-1 for workers
let total_participants = 4;

// Generate proof distributedly
match MyGroth16::prove_distributed(
    &proving_key,
    circuit,
    &mut thread_rng(),
    participant_id,
    total_participants,
    None, // No existing partial results
)? {
    Either::Left(proof) => {
        // Coordinator receives the final proof
        println!("Final proof generated!");
    },
    Either::Right(partial_results) => {
        // Workers receive partial MSM results
        // Send these to the coordinator
        println!("Partial results computed for participant {}", participant_id);
    }
}
```

### Coordinator Workflow

The coordinator (participant 0) collects partial results from all workers:

```rust
// Coordinator collects partial results from workers
let mut all_partial_results = vec![];

// Compute own partial result
match MyGroth16::prove_distributed(pk, circuit.clone(), &mut rng, 0, total, None)? {
    Either::Right(partial) => all_partial_results.push(partial),
    Either::Left(_) => unreachable!(), // Coordinator with no partials should return Right
}

// Collect from workers (in practice, received over network)
// all_partial_results.extend(worker_partials);

// Generate final proof with all partial results
match MyGroth16::prove_distributed(pk, circuit, &mut rng, 0, total, Some(&all_partial_results))? {
    Either::Left(proof) => {
        // Final proof ready
        println!("Distributed proof generation complete!");
    },
    Either::Right(_) => unreachable!(), // Should return final proof
}
```

### Checkpointed Proof Generation

For long-running computations, use checkpointed generation to save intermediate results:

```rust
// Compute MSM results with checkpointing
let checkpoint_dir = "./proof_checkpoints";
let total_chunks = 8; // Split computation into 8 chunks

let msm_results = MyGroth16::compute_msm_checkpointed(
    &proving_key,
    &h_poly,
    &input_assignment,
    &aux_assignment,
    total_chunks,
    Some(checkpoint_dir),
);

// Generate final proof from cached MSM results
let r = Fr::rand(&mut rng);
let s = Fr::rand(&mut rng);

let proof = MyGroth16::create_proof_from_msm_results(
    &proving_key,
    r,
    s,
    msm_results,
)?;
```

### Manual MSM Combination

For custom distributed setups, you can manually combine partial MSM results:

```rust
// Collect partial MSM results from multiple sources
let partial_results: Vec<(G1, G1, G1, G1, G2)> = collect_from_workers();

// Combine partial results
let combined_msm = MyGroth16::combine_partial_msm_results(&partial_results);

// Create final proof
let proof = MyGroth16::create_proof_from_msm_results(&pk, r, s, combined_msm)?;
```

### Advanced Usage

For more control over the distributed process:

```rust
// Create proof with specific randomness
let proof_result = MyGroth16::create_proof_distributed(
    circuit,
    &proving_key,
    r, // specific r value
    s, // specific s value
    participant_id,
    total_participants,
    partial_results_option,
)?;
```

The distributed and checkpointed APIs are designed to be drop-in replacements for the standard proof generation while providing additional flexibility for large-scale and resumable computations.

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Acknowledgements

This work was supported by:
a Google Faculty Award;
the National Science Foundation;
the UC Berkeley Center for Long-Term Cybersecurity;
and donations from the Ethereum Foundation, the Interchain Foundation, and Qtum.

An earlier version of this library was developed as part of the paper _"[ZEXE: Enabling Decentralized Private Computation][zexe]"_.

[zexe]: https://ia.cr/2018/962
