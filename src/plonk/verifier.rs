use super::structs::{
    BatchProof, Challenges, PlookupProof, ProofEvaluations, ScalarsAndBases, VerifyingKey,
};
use crate::{
    constants::*,
    errors::{PlonkError, SnarkError::ParameterError},
    proof_system::structs::{eval_merged_lookup_witness, eval_merged_table, OpenKey},
    transcript::*,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{format, vec, vec::Vec};
use core::ops::Neg;
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{constants::GATE_WIDTH, gadgets::ecc::SWToTEConParam};
use jf_utils::multi_pairing;


/// (Aggregated) polynomial commitment evaluation info.
/// * `u` - a random combiner that was used to combine evaluations at point
///   `eval_point` and `next_eval_point`.
/// * `eval_point` - the point to be evaluated at.
/// * `next_eval_point` - the shifted point to be evaluated at.
/// * `eval` - the (aggregated) polynomial evaluation value.
/// * `comm_scalars_and_bases` - the scalars-and-bases form of the (aggregated)
///   polynomial commitment.
/// * `opening_proof` - (aggregated) proof of evaluations at point `eval_point`.
/// * `shifted_opening_proof` - (aggregated) proof of evaluations at point
///   `next_eval_point`.
#[derive(Debug)]
pub(crate) struct PcsInfo<E: Pairing> {
    pub(crate) u: E::ScalarField,
    pub(crate) eval_point: E::ScalarField,
    pub(crate) next_eval_point: E::ScalarField,
    pub(crate) eval: E::ScalarField,
    pub(crate) comm_scalars_and_bases: ScalarsAndBases<E>,
    pub(crate) opening_proof: Commitment<E>,
    pub(crate) shifted_opening_proof: Commitment<E>,
}

pub(crate) struct Verifier<E: Pairing> {
    pub(crate) domain: Radix2EvaluationDomain<E::ScalarField>,
}

impl<E, F, P> Verifier<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    /// Construct a Plonk verifier that uses a domain with size `domain_size`.
    pub(crate) fn new(domain_size: usize) -> Result<Self, PlonkError> {

    }

    /// Prepare the (aggregated) polynomial commitment evaluation information.
    pub(crate) fn prepare_pcs_info<T>(
        &self,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::ScalarField]],
        batch_proof: &BatchProof<E>,
        extra_transcript_init_msg: &Option<Vec<u8>>,
    ) -> Result<PcsInfo<E>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
       
        

        // compute challenges and evaluations
        
        // pre-compute alpha related values
        
        // build the (aggregated) polynomial commitment/evaluation instance
        
    }

    /// Batchly verify multiple (aggregated) PCS opening proofs.
    ///
    /// We need to verify that
    /// - `e(Ai, [x]2) = e(Bi, [1]2) for i \in {0, .., m-1}`, where
    /// - `Ai = [open_proof_i] + u_i * [shifted_open_proof_i]` and
    /// - `Bi = eval_point_i * [open_proof_i] + u_i * next_eval_point_i *
    ///   [shifted_open_proof_i] + comm_i - eval_i * [1]1`.
    /// By Schwartz-Zippel lemma, it's equivalent to check that for a random r:
    /// - `e(A0 + ... + r^{m-1} * Am, [x]2) = e(B0 + ... + r^{m-1} * Bm, [1]2)`.
    pub(crate) fn batch_verify_opening_proofs<T>(
        open_key: &OpenKey<E>,
        pcs_infos: &[PcsInfo<E>],
    ) -> Result<bool, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        // Compute a pseudorandom challenge from the instances

        // Compute A := A0 + r * A1 + ... + r^{m-1} * Am
        
        // Add (A, [x]2) to the product pairing list

        // Compute B := B0 + r * B1 + ... + r^{m-1} * Bm

        // Add (-B, [1]2) to the product pairing list
        
        // Check e(A, [x]2) ?= e(B, [1]2)
        
    }

    /// Compute verifier challenges `tau`, `beta`, `gamma`, `alpha`, `zeta`,
    /// 'v', 'u'.
    #[inline]
    pub(crate) fn compute_challenges<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::ScalarField]],
        batch_proof: &BatchProof<E>,
        extra_transcript_init_msg: &Option<Vec<u8>>,
    ) -> Result<Challenges<E::ScalarField>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
       
    }

    /// Compute the constant term of the linearization polynomial:
    /// For each instance j:
    ///
    /// r_plonk_j = PI - L1(x) * alpha^2 -
    ///             alpha * \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} +
    /// gamma) * (w_{j,m} + gamma) * z_j(xw)
    ///
    /// r_lookup_j = alpha^3 * Ln(x) * (h1_x_j - h2_wx_j) -
    ///              alpha^4 * L1(x) * alpha -
    ///              alpha^5 * Ln(x) -
    ///              alpha^6 * (x - g^{n-1}) * prod_poly_wx_j * [gamma(1+beta) +
    /// h1_x_j + beta * h1_wx_j] * [gamma(1+beta) + beta * h2_wx_j]
    ///
    /// r_0 = \sum_{j=1..m} alpha^{k_j} * (r_plonk_j + (r_lookup_j))
    /// where m is the number of instances, and k_j is the number of alpha power
    /// terms added to the first j-1 instances.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_lin_poly_constant_term(
        &self,
        challenges: &Challenges<E::ScalarField>,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::ScalarField]],
        batch_proof: &BatchProof<E>,
        vanish_eval: &E::ScalarField,
        lagrange_1_eval: &E::ScalarField,
        lagrange_n_eval: &E::ScalarField,
        alpha_powers: &[E::ScalarField],
        alpha_bases: &[E::ScalarField],
    ) -> Result<E::ScalarField, PlonkError> {
       
    }

    /// Aggregate polynomial commitments into a single commitment (in the
    /// ScalarsAndBases form). Useful in batch opening.
    /// The verification key type is guaranteed to match the Plonk proof type.
    /// The returned commitment is a generalization of `[F]1` described in Sec 8.4, step 10 of https://eprint.iacr.org/2019/953.pdf
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn aggregate_poly_commitments(
        &self,
        vks: &[&VerifyingKey<E>],
        challenges: &Challenges<E::ScalarField>,
        vanish_eval: &E::ScalarField,
        lagrange_1_eval: &E::ScalarField,
        lagrange_n_eval: &E::ScalarField,
        batch_proof: &BatchProof<E>,
        alpha_powers: &[E::ScalarField],
        alpha_bases: &[E::ScalarField],
    ) -> Result<(ScalarsAndBases<E>, Vec<E::ScalarField>), PlonkError> {

        // Compute the first part of the batched polynomial commitment `[D]1` described in Sec 8.4, step 9 of https://eprint.iacr.org/2019/953.pdf

        // the random combiner term for the polynomials evaluated at point `zeta`
        
        // the random combiner term for the polynomials evaluated at point `zeta * g`

        // return buffer for aggregate_evaluations computation
    
            // Add poly commitments to be evaluated at point `zeta`.
            // Add wire witness polynomial commitments.
            // Add wire sigma polynomial commitments. The last sigma commitment is excluded.
            // Add poly commitments to be evaluated at point `zeta * g`.
            // Add Plookup polynomial commitments
        }

    
}

/// Private helper methods
impl<E, F, P> Verifier<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    /// Merge a polynomial commitment into the aggregated polynomial commitment
    /// (in the ScalarAndBases form), update the random combiner afterward.
    #[inline]
    fn add_poly_comm(
        scalar_and_bases: &mut ScalarsAndBases<E>,
        random_combiner: &mut E::ScalarField,
        comm: E::G1Affine,
        r: E::ScalarField,
    ) {

    }

    /// Add a polynomial commitment evaluation value to the aggregated
    /// polynomial evaluation, update the random combiner afterward.
    #[inline]
    fn add_pcs_eval(
        result: &mut E::ScalarField,
        random_combiner: &E::ScalarField,
        eval: E::ScalarField,
    ) {

    }

    /// Evaluate vanishing polynomial at point `zeta`
    #[inline]
    pub(crate) fn evaluate_vanishing_poly(&self, zeta: &E::ScalarField) -> E::ScalarField {

    }

    /// Evaluate the first and the last lagrange polynomial at point `zeta`
    /// given the vanishing polynomial evaluation `vanish_eval`.
    #[inline]
    pub(crate) fn evaluate_lagrange_1_and_n(
        &self,
        zeta: &E::ScalarField,
        vanish_eval: &E::ScalarField,
    ) -> (E::ScalarField, E::ScalarField) {

    }

    #[inline]
    /// Return the list of polynomial commitments to be opened at point `zeta`.
    /// The order should be consistent with the prover side.
    fn plookup_open_poly_comms(
        proof: &PlookupProof<E>,
        vk: &VerifyingKey<E>,
    ) -> Result<Vec<Commitment<E>>, PlonkError> {

    }

    #[inline]
    /// Return the list of polynomial commitments to be opened at point `zeta *
    /// g`. The order should be consistent with the prover side.
    fn plookup_shifted_open_poly_comms(
        proof: &PlookupProof<E>,
        vk: &VerifyingKey<E>,
        wires_poly_comms: &[Commitment<E>],
    ) -> Result<Vec<Commitment<E>>, PlonkError> {

    }

    /// Evaluate public input polynomial at point `z`.
    /// Define the following as
    /// - H: The domain with generator g
    /// - n: The size of the domain H
    /// - Z_H: The vanishing polynomial for H.
    /// - v_i: A sequence of values, where v_i = g^i / n
    ///
    /// We then compute L_{i,H}(z) as `L_{i,H}(z) = Z_H(z) * v_i / (z - g^i)`
    /// The public input polynomial evaluation is:
    ///
    /// \sum_{i=0..l} L_{i,H}(z) * pub_input[i].
    ///
    /// For merged circuits, the evaluation is:
    /// \sum_{i=0..l/2} L_{i,H}(z) * pub_input[i] + \sum_{i=0..l/2} L_{n-i,H}(z)
    /// * pub_input[l/2+i]
    ///
    /// TODO: reuse the lagrange values
    pub(crate) fn evaluate_pi_poly(
        &self,
        pub_input: &[E::ScalarField],
        z: &E::ScalarField,
        vanish_eval: &E::ScalarField,
        circuit_is_merged: bool,
    ) -> Result<E::ScalarField, PlonkError> {
        // If z is a root of the vanishing polynomial, directly return zero.

    }
}