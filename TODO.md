Implement a distributed version and a checkpointed version of Groth16 using the existing codebase, making as few changes as possible.
The idea is as follows.
The core function is `create_proof_with_assignment` in `src/prover.rs`.
First, split the content of this function into two parts, one is called `compute_all_msm_in_proof_generation`, which receives the same inputs as `create_proof_with_assignment`, but only computes the MSMs (there should be 6 of them), and returns the results of these MSMs as a tuple of group elements.
Then, let the function `create_proof_with_intermediate_results` receive only `pk, r, s` of `create_proof_with_assignment` as inputs, and also receives the tuple of group elements from `compute_all_msm_in_proof_generation`, and finishes the rest works of `create_proof_with_assignment`.

Next, create a distributed version of `compute_all_msm_in_proof_generation`, which additionally receives a pair `(i, total)` indicating the index of the current participant and total number of participants.
Most of the logic of this function should be the same as the original function, except that all the MSMs are distributed across multiple machines.
More specifically, the function should only compute the part of the MSM slice corresponding to `i`, and returns the six partial MSM results.

Next, create a `combine_partial_msm_results` function that takes a list of partial MSM results and combines them into a single MSM result.

## Distributed Groth16 Implementation

Create the distributed versions of `prove` for Groth16 in `src/lib.rs`, and `create_random_proof_with_reduction`, `create_proof_with_reduction`, `create_proof_with_assignment` in `src/prover.rs`.
These functions additionally receive a pair `(i, total)` and optionally additionally receive the partial MSM results from other participants. If `i != 0`, the function should invoke the distributed version of `compute_all_msm_in_proof_generation` with the same `(i, total)`, and directly returns the partial MSM results, without proceeding further.
If `i == 0`, the function should invoke the distributed version of `compute_all_msm_in_proof_generation` with `(0, total)`, and then invoke `combine_partial_msm_results` to combine the collected partial MSM results, and proceeds the same as the non-distributed version.

## Checkpointed Groth16 Implementation

Create a checkpointed version of `compute_all_msm_in_proof_generation`, which receives the same inputs as `compute_all_msm_in_proof_generation`, but invokes the distributed version of `compute_all_msm_in_proof_generation` internally. Specifically, it invokes the distributed version of `compute_all_msm_in_proof_generation` with `(i, total)` for each `i` from `0` to `total-1`, collects the partial MSM results from all the participants, combine them using `combine_partial_msm_results`, and returns the final MSM result. Moreover, before computing each partial MSM result, it should check the file system if the result exists, and if so, load it from the file; after computing each partial MSM result, it saves the result to a file.
