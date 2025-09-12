//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

#[cfg(test)]
mod test;

pub use self::{data_structures::*, prover::Either, verifier::*};

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::{marker::PhantomData, rand::RngCore, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing, QAP: R1CSToQAP> SNARK<E::ScalarField> for Groth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(&circuit_pvk, proof, &x)?)
    }
}

impl<E: Pairing, QAP: R1CSToQAP> CircuitSpecificSetupSNARK<E::ScalarField> for Groth16<E, QAP> {}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Distributed version of prove function.
    /// If i != 0, returns partial MSM results. If i == 0, combines all partial
    /// results and creates the final proof.
    pub fn prove_distributed<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> Result<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>, SynthesisError> {
        Self::create_random_proof_with_reduction_distributed(
            circuit,
            pk,
            rng,
            i,
            total,
            partial_results,
        )
    }

    /// Create a Groth16 proof using randomness and distributed computation.
    /// This method samples randomness for zero knowledges via `rng`.
    pub fn create_random_proof_distributed<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut R,
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> Result<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>, SynthesisError> {
        Self::create_random_proof_with_reduction_distributed(
            circuit,
            pk,
            rng,
            i,
            total,
            partial_results,
        )
    }

    /// Create a Groth16 proof using specified randomness and distributed
    /// computation.
    pub fn create_proof_distributed<C: ConstraintSynthesizer<E::ScalarField>>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> Result<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>, SynthesisError> {
        Self::create_proof_with_reduction_distributed(circuit, pk, r, s, i, total, partial_results)
    }

    /// Checkpointed version of MSM computation that uses filesystem caching.
    /// This method saves intermediate results to disk and can resume
    /// computation.
    pub fn compute_msm_checkpointed(
        pk: &ProvingKey<E>,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
        total: usize,
        checkpoint_dir: Option<&str>,
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        Self::compute_all_msm_in_proof_generation_checkpointed(
            pk,
            h,
            input_assignment,
            aux_assignment,
            total,
            checkpoint_dir,
        )
    }

    /// Create proof using pre-computed MSM results from checkpointed
    /// computation.
    pub fn create_proof_from_msm_results(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        msm_results: (E::G1, E::G1, E::G1, E::G1, E::G2),
    ) -> Result<Proof<E>, SynthesisError> {
        Self::create_proof_with_intermediate_results(pk, r, s, msm_results)
    }

    /// Combine partial MSM results from multiple participants into a single
    /// result.
    pub fn combine_partial_msm_results(
        partial_results: &[(E::G1, E::G1, E::G1, E::G1, E::G2)],
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        Self::combine_partial_msm_results_internal(partial_results)
    }
}
