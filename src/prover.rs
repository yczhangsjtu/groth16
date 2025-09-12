use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    Result as R1CSResult,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter,
    ops::{AddAssign, Mul},
    rand::Rng,
    vec::Vec,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use std::{fs, path::Path};

/// Either type for distributed proof generation results
#[derive(Debug)]
pub enum Either<L, R> {
    /// Left variant containing the final proof (coordinator result)
    Left(L),
    /// Right variant containing partial MSM results (participant result)
    Right(R),
}

type D<F> = GeneralEvaluationDomain<F>;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        matrices: &ConstraintMatrices<E::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map_from_matrices::<E::ScalarField, D<E::ScalarField>>(
            matrices,
            num_inputs,
            num_constraints,
            full_assignment,
        )?;
        end_timer!(witness_map_time);
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];
        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;
        end_timer!(prover_time);

        Ok(proof)
    }

    /// Compute all MSMs needed for proof generation.
    /// Returns (h_acc, l_aux_acc, a_msm, b_g1_msm, b_g2_msm) as a tuple of
    /// group elements.
    #[inline]
    fn compute_all_msm_in_proof_generation(
        pk: &ProvingKey<E>,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        // Compute h_acc MSM
        let h_assignment = cfg_into_iter!(h)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);
        drop(h_assignment);

        // Compute l_aux_acc MSM
        let aux_assignment_bigint = cfg_iter!(aux_assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_assignment_bigint);

        // Prepare full assignment for A and B computations
        let input_assignment_bigint = input_assignment
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let assignment = [&input_assignment_bigint[..], &aux_assignment_bigint[..]].concat();

        // Compute A MSM
        let a_msm = E::G1::msm_bigint(&pk.a_query[1..], &assignment);

        // Compute B in G1 MSM
        let b_g1_msm = E::G1::msm_bigint(&pk.b_g1_query[1..], &assignment);

        // Compute B in G2 MSM
        let b_g2_msm = E::G2::msm_bigint(&pk.b_g2_query[1..], &assignment);

        (h_acc, l_aux_acc, a_msm, b_g1_msm, b_g2_msm)
    }

    /// Distributed version of compute_all_msm_in_proof_generation.
    /// Computes only the MSM slice for participant i out of total participants.
    #[inline]
    fn compute_all_msm_in_proof_generation_distributed(
        pk: &ProvingKey<E>,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
        i: usize,
        total: usize,
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        // Calculate slice boundaries for this participant
        let slice_size = |len: usize| -> (usize, usize) {
            let base_size = len / total;
            let remainder = len % total;
            let start = i * base_size + std::cmp::min(i, remainder);
            let size = base_size + if i < remainder { 1 } else { 0 };
            (start, size)
        };

        // Compute h_acc MSM (partial)
        let h_assignment = cfg_into_iter!(h)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let (h_start, h_size) = slice_size(pk.h_query.len());
        let h_acc = if h_size > 0 && h_start < pk.h_query.len() {
            let h_end = std::cmp::min(h_start + h_size, pk.h_query.len());
            let h_slice = &h_assignment[h_start..h_end];
            let query_slice = &pk.h_query[h_start..h_end];
            E::G1::msm_bigint(query_slice, h_slice)
        } else {
            E::G1::zero()
        };

        // Compute l_aux_acc MSM (partial)
        let aux_assignment_bigint = cfg_iter!(aux_assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let (l_start, l_size) = slice_size(pk.l_query.len());
        let l_aux_acc = if l_size > 0 && l_start < pk.l_query.len() {
            let l_end = std::cmp::min(l_start + l_size, pk.l_query.len());
            let aux_slice = &aux_assignment_bigint[l_start..l_end];
            let query_slice = &pk.l_query[l_start..l_end];
            E::G1::msm_bigint(query_slice, aux_slice)
        } else {
            E::G1::zero()
        };

        // Prepare full assignment for A and B computations
        let input_assignment_bigint = input_assignment
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let assignment = [&input_assignment_bigint[..], &aux_assignment_bigint[..]].concat();

        // Compute A MSM (partial)
        let a_query_main = &pk.a_query[1..]; // Skip first element
        let (a_start, a_size) = slice_size(a_query_main.len());
        let a_msm = if a_size > 0 && a_start < a_query_main.len() {
            let a_end = std::cmp::min(a_start + a_size, a_query_main.len());
            let assignment_slice = &assignment[a_start..a_end];
            let query_slice = &a_query_main[a_start..a_end];
            E::G1::msm_bigint(query_slice, assignment_slice)
        } else {
            E::G1::zero()
        };

        // Compute B in G1 MSM (partial)
        let b_g1_query_main = &pk.b_g1_query[1..]; // Skip first element
        let (b_g1_start, b_g1_size) = slice_size(b_g1_query_main.len());
        let b_g1_msm = if b_g1_size > 0 && b_g1_start < b_g1_query_main.len() {
            let b_g1_end = std::cmp::min(b_g1_start + b_g1_size, b_g1_query_main.len());
            let assignment_slice = &assignment[b_g1_start..b_g1_end];
            let query_slice = &b_g1_query_main[b_g1_start..b_g1_end];
            E::G1::msm_bigint(query_slice, assignment_slice)
        } else {
            E::G1::zero()
        };

        // Compute B in G2 MSM (partial)
        let b_g2_query_main = &pk.b_g2_query[1..]; // Skip first element
        let (b_g2_start, b_g2_size) = slice_size(b_g2_query_main.len());
        let b_g2_msm = if b_g2_size > 0 && b_g2_start < b_g2_query_main.len() {
            let b_g2_end = std::cmp::min(b_g2_start + b_g2_size, b_g2_query_main.len());
            let assignment_slice = &assignment[b_g2_start..b_g2_end];
            let query_slice = &b_g2_query_main[b_g2_start..b_g2_end];
            E::G2::msm_bigint(query_slice, assignment_slice)
        } else {
            E::G2::zero()
        };

        (h_acc, l_aux_acc, a_msm, b_g1_msm, b_g2_msm)
    }

    /// Internal function to combine partial MSM results from multiple
    /// participants. Takes a list of partial MSM results and combines them
    /// into a single result.
    #[inline]
    pub fn combine_partial_msm_results_internal(
        partial_results: &[(E::G1, E::G1, E::G1, E::G1, E::G2)],
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        let mut combined_h_acc = E::G1::zero();
        let mut combined_l_aux_acc = E::G1::zero();
        let mut combined_a_msm = E::G1::zero();
        let mut combined_b_g1_msm = E::G1::zero();
        let mut combined_b_g2_msm = E::G2::zero();

        for (h_acc, l_aux_acc, a_msm, b_g1_msm, b_g2_msm) in partial_results {
            combined_h_acc += h_acc;
            combined_l_aux_acc += l_aux_acc;
            combined_a_msm += a_msm;
            combined_b_g1_msm += b_g1_msm;
            combined_b_g2_msm += b_g2_msm;
        }

        (
            combined_h_acc,
            combined_l_aux_acc,
            combined_a_msm,
            combined_b_g1_msm,
            combined_b_g2_msm,
        )
    }

    /// Checkpointed version of compute_all_msm_in_proof_generation.
    /// Uses filesystem to cache partial results and randominvokes the
    /// distributed version internally.
    #[inline]
    pub fn compute_all_msm_in_proof_generation_checkpointed(
        pk: &ProvingKey<E>,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
        total: usize,
        checkpoint_dir: Option<&str>,
    ) -> (E::G1, E::G1, E::G1, E::G1, E::G2) {
        let mut partial_results = Vec::new();
        let checkpoint_path = checkpoint_dir.unwrap_or("./checkpoints");

        // Create checkpoint directory if it doesn't exist
        if let Err(_) = fs::create_dir_all(checkpoint_path) {
            // If we can't create directory, proceed without checkpointing
        }

        for i in 0..total {
            let checkpoint_file = format!("{}/msm_result_{}_{}.bin", checkpoint_path, i, total);

            // Try to load from checkpoint
            let result = if Path::new(&checkpoint_file).exists() {
                // Try to load from file
                match Self::load_partial_msm_result(&checkpoint_file) {
                    Ok(result) => result,
                    Err(_) => {
                        panic!("Failed to load partial MSM result")
                    },
                }
            } else {
                // Compute and save
                let result = Self::compute_all_msm_in_proof_generation_distributed(
                    pk,
                    h,
                    input_assignment,
                    aux_assignment,
                    i,
                    total,
                );
                Self::save_partial_msm_result(&result, &checkpoint_file)
                    .expect("Failed to save partial MSM result");
                result
            };

            partial_results.push(result);
        }

        Self::combine_partial_msm_results_internal(&partial_results)
    }

    /// Save partial MSM result to file using arkworks serialization.
    #[inline]
    fn save_partial_msm_result(
        result: &(E::G1, E::G1, E::G1, E::G1, E::G2),
        path: &str,
    ) -> Result<(), std::io::Error> {
        let mut buffer = Vec::new();
        result.serialize_uncompressed(&mut buffer).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Serialization error: {}", e),
            )
        })?;
        fs::write(path, buffer)?;
        Ok(())
    }

    /// Load partial MSM result from file using arkworks deserialization.
    #[inline]
    fn load_partial_msm_result(
        path: &str,
    ) -> Result<(E::G1, E::G1, E::G1, E::G1, E::G2), std::io::Error> {
        let buffer = fs::read(path)?;
        let result = <(E::G1, E::G1, E::G1, E::G1, E::G2)>::deserialize_uncompressed(&*buffer)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Deserialization error: {}", e),
                )
            })?;
        Ok(result)
    }

    /// Save randomness values r and s to file.
    #[inline]
    fn save_randomness(
        r: &E::ScalarField,
        s: &E::ScalarField,
        path: &str,
    ) -> Result<(), std::io::Error> {
        let mut buffer = Vec::new();
        (*r, *s).serialize_compressed(&mut buffer).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Randomness serialization error: {}", e),
            )
        })?;
        fs::write(path, buffer)?;
        Ok(())
    }

    /// Load randomness values r and s from file.
    #[inline]
    fn load_randomness(path: &str) -> Result<(E::ScalarField, E::ScalarField), std::io::Error> {
        let buffer = fs::read(path)?;
        let result =
            <(E::ScalarField, E::ScalarField)>::deserialize_compressed(&*buffer).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Randomness deserialization error: {}", e),
                )
            })?;
        Ok(result)
    }

    /// Distributed version of create_proof_with_assignment.
    /// If i != 0, returns partial MSM results. If i == 0, combines all partial
    /// results and creates the final proof.
    #[inline]
    fn create_proof_with_assignment_distributed(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> R1CSResult<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>> {
        if i != 0 {
            // Non-coordinator: compute and return partial MSM results
            let partial = Self::compute_all_msm_in_proof_generation_distributed(
                pk,
                h,
                input_assignment,
                aux_assignment,
                i,
                total,
            );
            Ok(Either::Right(partial))
        } else {
            // Coordinator: collect partial results and create final proof
            let mut all_partials = vec![Self::compute_all_msm_in_proof_generation_distributed(
                pk,
                h,
                input_assignment,
                aux_assignment,
                0,
                total,
            )];

            if let Some(partials) = partial_results {
                all_partials.extend_from_slice(partials);
            }

            let combined_results = Self::combine_partial_msm_results_internal(&all_partials);
            let proof = Self::create_proof_with_intermediate_results(pk, r, s, combined_results)?;
            Ok(Either::Left(proof))
        }
    }

    /// Distributed version of create_proof_with_reduction.
    #[inline]
    pub fn create_proof_with_reduction_distributed<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> R1CSResult<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let result = Self::create_proof_with_assignment_distributed(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
            i,
            total,
            partial_results,
        );

        end_timer!(prover_time);
        result
    }

    /// Distributed version of create_random_proof_with_reduction.
    #[inline]
    pub fn create_random_proof_with_reduction_distributed<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
        i: usize,
        total: usize,
        partial_results: Option<&[(E::G1, E::G1, E::G1, E::G1, E::G2)]>,
    ) -> R1CSResult<Either<Proof<E>, (E::G1, E::G1, E::G1, E::G1, E::G2)>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::create_proof_with_reduction_distributed(circuit, pk, r, s, i, total, partial_results)
    }

    /// Create proof using intermediate MSM results.
    /// Takes only pk, r, s and the tuple of MSM results.
    #[inline]
    pub fn create_proof_with_intermediate_results(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        msm_results: (E::G1, E::G1, E::G1, E::G1, E::G2),
    ) -> R1CSResult<Proof<E>> {
        let (h_acc, l_aux_acc, a_msm, b_g1_msm, b_g2_msm) = msm_results;

        // Compute A
        let r_g1 = pk.delta_g1.mul(r);
        let mut g_a = r_g1;
        g_a.add_assign(&pk.a_query[0]);
        g_a += &a_msm;
        g_a.add_assign(&pk.vk.alpha_g1);

        let s_g_a = g_a * &s;

        // Compute B in G1 if needed
        let g1_b = if !r.is_zero() {
            let s_g1 = pk.delta_g1.mul(s);
            let mut g1_b = s_g1;
            g1_b.add_assign(&pk.b_g1_query[0]);
            g1_b += &b_g1_msm;
            g1_b.add_assign(&pk.beta_g1);
            g1_b
        } else {
            E::G1::zero()
        };

        // Compute B in G2
        let s_g2 = pk.vk.delta_g2.mul(s);
        let mut g2_b = s_g2;
        g2_b.add_assign(&pk.b_g2_query[0]);
        g2_b += &b_g2_msm;
        g2_b.add_assign(&pk.vk.beta_g2);

        let r_g1_b = g1_b * &r;
        let r_s_delta_g1 = pk.delta_g1 * (r * s);

        // Compute C
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
    }

    #[inline]
    fn create_proof_with_assignment(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let msm_results =
            Self::compute_all_msm_in_proof_generation(pk, h, input_assignment, aux_assignment);
        Self::create_proof_with_intermediate_results(pk, r, s, msm_results)
    }

    #[inline]
    fn create_proof_with_assignment_checkpointed(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
        total: usize,
        checkpoint_dir: Option<&str>,
    ) -> R1CSResult<Proof<E>> {
        let msm_results = Self::compute_all_msm_in_proof_generation_checkpointed(
            pk,
            h,
            input_assignment,
            aux_assignment,
            total,
            checkpoint_dir,
        );
        Self::create_proof_with_intermediate_results(pk, r, s, msm_results)
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// This method samples randomness for zero knowledges via `rng`.
    #[inline]
    pub fn create_random_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::create_proof_with_reduction(circuit, pk, r, s)
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// This method samples randomness for zero knowledges via `rng`.
    #[inline]
    pub fn create_random_proof_with_reduction_checkpointed<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
        total: usize,
        checkpoint_dir: Option<&str>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let checkpoint_path = checkpoint_dir.unwrap_or("./checkpoints");

        // Create checkpoint directory if it doesn't exist
        let _ = fs::create_dir_all(checkpoint_path);

        let randomness_file = format!("{}/randomness.bin", checkpoint_path);

        // Try to load existing randomness, or generate new if not found
        let (r, s) = if Path::new(&randomness_file).exists() {
            match Self::load_randomness(&randomness_file) {
                Ok((r, s)) => (r, s),
                Err(_) => {
                    // If loading fails, generate new randomness and save
                    let r = E::ScalarField::rand(rng);
                    let s = E::ScalarField::rand(rng);
                    let _ = Self::save_randomness(&r, &s, &randomness_file);
                    (r, s)
                },
            }
        } else {
            // Generate new randomness and save
            let r = E::ScalarField::rand(rng);
            let s = E::ScalarField::rand(rng);
            let _ = Self::save_randomness(&r, &s, &randomness_file);
            (r, s)
        };

        Self::create_proof_with_reduction_checkpointed(circuit, pk, r, s, total, checkpoint_dir)
    }

    /// Create a Groth16 proof that is *not* zero-knowledge with the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction_no_zk<C>(
        circuit: C,
        pk: &ProvingKey<E>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        Self::create_proof_with_reduction(
            circuit,
            pk,
            E::ScalarField::zero(),
            E::ScalarField::zero(),
        )
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<Proof<E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction_checkpointed<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        total: usize,
        checkpoint_dir: Option<&str>,
    ) -> R1CSResult<Proof<E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment_checkpointed(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
            total,
            checkpoint_dir,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    /// Given a Groth16 proof, returns a fresh proof of the same statement. For
    /// a proof π of a statement S, the output of the non-deterministic
    /// procedure `rerandomize_proof(π)` is statistically indistinguishable
    /// from a fresh honest proof of S. For more info, see theorem 3 of [\[BKSV20\]](https://eprint.iacr.org/2020/811)
    pub fn rerandomize_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        rng: &mut impl Rng,
    ) -> Proof<E> {
        // These are our rerandomization factors. They must be nonzero and uniformly
        // sampled.
        let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
        while r1.is_zero() || r2.is_zero() {
            r1 = E::ScalarField::rand(rng);
            r2 = E::ScalarField::rand(rng);
        }

        // See figure 1 in the paper referenced above:
        //   A' = (1/r₁)A
        //   B' = r₁B + r₁r₂(δG₂)
        //   C' = C + r₂A

        // We can unwrap() this because r₁ is guaranteed to be nonzero
        let new_a = proof.a.mul(r1.inverse().unwrap());
        let new_b = proof.b.mul(r1) + &vk.delta_g2.mul(r1 * &r2);
        let new_c = proof.c + proof.a.mul(r2).into_affine();

        Proof {
            a: new_a.into_affine(),
            b: new_b.into_affine(),
            c: new_c.into_affine(),
        }
    }
}
