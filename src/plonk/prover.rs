// use core::ops::Neg;

// use super::structs::{
//     eval_merged_lookup_witness, eval_merged_table, Challenges, Oracles, PlookupEvaluations,
//     PlookupOracles, ProofEvaluations, ProvingKey,
// };
// use crate::{
//     constants::domain_size_ratio,
//     errors::{PlonkError, SnarkError::*},
//     proof_system::structs::CommitKey,
// };
// use ark_ec::pairing::Pairing;
// use ark_ff::{FftField, Field, One, UniformRand, Zero};
// use ark_poly::{
//     univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
//     Polynomial, Radix2EvaluationDomain,
// };
// use ark_std::{
//     rand::{CryptoRng, RngCore},
//     string::ToString,
//     vec,
//     vec::Vec,
// };
// use jf_primitives::pcs::{
//     prelude::{Commitment, UnivariateKzgPCS},
//     PolynomialCommitmentScheme,
// };
// use jf_relation::{constants::GATE_WIDTH, Arithmetization};
// use jf_utils::par_utils::parallelizable_slice_iter;
// #[cfg(feature = "parallel")]
// use rayon::prelude::*;

/// 用来存储一组承诺和承诺对应的多项式
type CommitmentsAndPolys<E> = (
    Vec<Commitment<E>>,
    Vec<DensePolynomial<<E as Pairing>::ScalarField>>,
);

/// A Plonk IOP prover.
/// 表示该项是对当前crate公开的，但对外部crate是私有的。
/// 这意味着，只有在当前crate内部，才能访问被pub(crate)修饰的项。
pub(crate) struct Prover<E: Pairing> {
    /// 用于存储多项式的评估域
    domain: Radix2EvaluationDomain<E::ScalarField>,
    /// 用于存储商多项式的评估域
    quot_domain: GeneralEvaluationDomain<E::ScalarField>,
}


impl<E: Pairing> Prover<E> {
    /// Construct a Plonk prover that uses a domain with size `domain_size` and
    /// quotient polynomial domain with a size that is larger than the degree of
    /// the quotient polynomial.
    /// * `num_wire_types` - number of wire types in the corresponding
    ///   constraint system.
    pub(crate) fn new(domain_size: usize, num_wire_types: usize) -> Result<Self, PlonkError> {
        
    }

    /// Round 1:
    /// 1. Compute and commit wire witness polynomials.
    /// 2. Compute public input polynomial.
    /// Return the wire witness polynomials and their commitments,
    /// also return the public input polynomial.
    /// 本质上在做的事情是通过输入constraint system，直接调用constraint system当中实现好的方法
    /// 即算得到wire witness polynomials和他们的承诺，以及公共输入多项式
    pub(crate) fn run_1st_round<C: Arithmetization<E::ScalarField>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        /// contraint system约束系统
        cs: &C,
    ) -> Result<(CommitmentsAndPolys<E>, DensePolynomial<E::ScalarField>), PlonkError> {
        /// 计算wire witness polynomials
        /// 调用约束系统(constraint system)的compute_wire_polynomials方法实现
        /// * constraint system的实现在relation/src/constraint_system.rs中
        /// 然后通过上面算法得到的wire witness polynomials，再逐一通过mask_polynomial方法进行隐藏处理
        
        /// 接受密钥和多项式，返回多项式的承诺
        
        /// 用constraint system当中实现的计算公共输入多项式的方法直接得到公共输入多项式
        
        /// 返回wire witness polynomials和他们的承诺，以及公共输入多项式
        
    }


    /// Round 2: Compute and commit the permutation grand product polynomial.
    /// Return the grand product polynomial and its commitment.
    /// 这一步骤本质上是通过cs当中实现好的功能直接得到当前证明系统对应的乘积置换多项式
    /// 并且返回mask好的乘积置换多项式和他的commitment
    pub(crate) fn run_2nd_round<C: Arithmetization<E::ScalarField>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
        challenges: &Challenges<E::ScalarField>,
    ) -> Result<(Commitment<E>, DensePolynomial<E::ScalarField>), PlonkError> {
        /// 直接调cs当中计算乘积多项式的方法得到乘积多项式，然后mask起来
        
        /// 得到乘积置换多项式的承诺
        
        /// 返回乘积置换多项式和它的commitment
        
    }

    
    /// Round 3: Return the split quotient polynomials and their commitments.
    /// Note that the first `num_wire_types`-1 split quotient polynomials
    /// have degree `domain_size`+1.
    /// 本质上是直接输入约束系统，调用这个文件中实现好的方法得到商多项式
    /// 然后调用这个文件里实现好的split_quotient_polynomial方法将商多项式分割成多个多项式
    /// 然后返回分割好的多项式和他们的承诺
    pub(crate) fn run_3rd_round<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        challenges: &Challenges<E::ScalarField>,
        online_oracles: &[Oracles<E::ScalarField>],
        num_wire_types: usize,
    ) -> Result<CommitmentsAndPolys<E>, PlonkError> {
        /// 计算商多项式
        
        /// 将商多项式分割成为多个多项式
        
        /// 计算分割之后的多项式的承诺
        
        /// 返回分割之后的多项式和他们的承诺

    }

    /// Round 4: Compute linearization polynomial and evaluate polynomials to be
    /// opened.
    /// 本质上是调出oracle当中的多项式（wire poly, sigma, permutation poly）
    /// 然后算这些多项式在zeta点的值，然后返回这些值
    ///
    /// Compute the polynomial evaluations for TurboPlonk.
    /// Return evaluations of the Plonk proof.
    pub(crate) fn compute_evaluations(
        &self,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::ScalarField>,
        online_oracles: &Oracles<E::ScalarField>,
        num_wire_types: usize,
    ) -> ProofEvaluations<E::ScalarField> {
        /// 计算了online_oracles.wire_polys中的每个多项式在challenges.zeta点的评估值，并将结果收集到一个向量中。
        
        /// 计算了pk.sigmas中的每个多项式在challenges.zeta点的评估值，并将结果收集到一个向量中。
        
        /// 计算了online_oracles.prod_perm_poly在challenges.zeta点的评估值

    }


    /// Compute (aggregated) polynomial opening proofs at point `zeta` and
    /// `zeta * domain_generator`. TODO: Parallelize the computation.
    pub(crate) fn compute_opening_proofs(
        &self,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        zeta: &E::ScalarField,
        v: &E::ScalarField,
        online_oracles: &[Oracles<E::ScalarField>],
        lin_poly: &DensePolynomial<E::ScalarField>,
    ) -> Result<(Commitment<E>, Commitment<E>), PlonkError> {
        
        // List the polynomials to be opened at point `zeta`.
        
        // List the polynomials to be opened at point `zeta * w`.
        
        
    }
}

/// Private helper methods
impl<E: Pairing> Prover<E> {

    /// Mask the polynomial so that it remains hidden after revealing
    /// `hiding_bound` evaluations.
    /// 本质上是希望将多项式poly隐藏起来，使得在hiding_bound个点上的值不被泄露
    /// 具体的实现是在ark_poly::univariate::DensePolynomial当中实现的
    fn mask_polynomial<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        poly: DensePolynomial<E::ScalarField>,
        hiding_bound: usize,
    ) -> DensePolynomial<E::ScalarField> {
        
    }

    /// Return a batched opening proof given a list of polynomials `polys_ref`,
    /// evaluation point `eval_point`, and randomized combiner `r`.
    fn compute_batched_witness_polynomial_commitment(
        ck: &CommitKey<E>,
        polys_ref: &[&DensePolynomial<E::ScalarField>],
        r: &E::ScalarField,
        eval_point: &E::ScalarField,
    ) -> Result<Commitment<E>, PlonkError> {
        // Compute the aggregated polynomial
        
        // Compute opening witness polynomial and its commitment
        
    }

    /// Compute the quotient polynomial via (i)FFTs.
    /// 本质上是在用FFT算法计算商多项式，这部分细节要看论文确认下
    fn compute_quotient_polynomial(
        &self,
        challenges: &Challenges<E::ScalarField>,
        pks: &[&ProvingKey<E>],
        online_oracles: &[Oracles<E::ScalarField>],
        num_wire_types: usize,
    ) -> Result<DensePolynomial<E::ScalarField>, PlonkError> {
       
        // Compute 1/Z_H(w^i).

        // Compute coset evaluations of the quotient polynomial.
       
        // enumerate proving instances
       
        // Compute the coefficient form of the quotient polynomial

    }

    // Compute the i-th coset evaluation of the circuit part of the quotient
    // polynomial.
    fn compute_quotient_circuit_contribution(
        i: usize,
        w: &[E::ScalarField],
        pi: &E::ScalarField,
        selectors_coset_fft: &[Vec<E::ScalarField>],
    ) -> E::ScalarField {
        // Selectors
        // The order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        
    }

    /// Compute the i-th coset evaluation of the copy constraint part of the
    /// quotient polynomial.
    /// `eval_point` - the evaluation point.
    /// `w` - the wire polynomial coset evaluations at `eval_point`.
    /// `z_x` - the permutation product polynomial evaluation at `eval_point`.
    /// `z_xw`-  the permutation product polynomial evaluation at `eval_point *
    /// g`, where `g` is the root of unity of the original domain.
    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_copy_constraint_contribution(
        i: usize,
        eval_point: E::ScalarField,
        pk: &ProvingKey<E>,
        w: &[E::ScalarField],
        z_x: &E::ScalarField,
        z_xw: &E::ScalarField,
        challenges: &Challenges<E::ScalarField>,
        sigmas_coset_fft: &[Vec<E::ScalarField>],
    ) -> (E::ScalarField, E::ScalarField) {
       
        // The check that:
        //   \prod_i [w_i(X) + beta * k_i * X + gamma] * z(X)
        // - \prod_i [w_i(X) + beta * sigma_i(X) + gamma] * z(wX) = 0
        // on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Extended permutation values
       
        // Compute the 1st term.
        
        // Minus the 2nd term.

        // The check that z(x) = 1 at point 1.
        // (z(x)-1) * L1(x) * alpha^2 / Z_H(x) = (z(x)-1) * alpha^2 / (n * (x - 1))
       
    }

    /// Compute the i-th coset evaluation of the lookup constraint part of the
    /// quotient polynomial.
    /// `eval_point`: the evaluation point.
    /// `pk`: proving key.
    /// `lookup_w`: (merged) lookup witness coset evaluations at `eval_point`.
    /// `h_coset_ffts`: coset evaluations for the sorted lookup vector
    /// polynomials. `prod_lookup_coset_fft`: coset evaluations for the
    /// Plookup product polynomial. `challenges`: Fiat-shamir challenges.
    ///
    /// The coset evaluations should be non-empty. The proving key should be
    /// guaranteed to support lookup.
    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_plookup_contribution(
        &self,
        i: usize,
        eval_point: E::ScalarField,
        pk: &ProvingKey<E>,
        w: &[E::ScalarField],
        w_next: &[E::ScalarField],
        h_coset_ffts: &[Vec<E::ScalarField>],
        prod_lookup_coset_fft: &[E::ScalarField],
        range_table_coset_fft: &[E::ScalarField],
        key_table_coset_fft: &[E::ScalarField],
        q_lookup_coset_fft: &[E::ScalarField],
        table_dom_sep_coset_fft: &[E::ScalarField],
        q_dom_sep_coset_fft: &[E::ScalarField],
        challenges: &Challenges<E::ScalarField>,
    ) -> (E::ScalarField, E::ScalarField) {
        

        // The check that h1(X) - h2(wX) = 0 at point w^{n-1}
        //
        // Fh(X)/Z_H(X) = (Ln(X) * (h1(X) - h2(wX))) / Z_H(X) = (h1(X) - h2(wX)) *
        // w^{n-1} / (n * (X - w^{n-1}))
       
        // The check that p(X) = 1 at point 1.
        //
        // Fp1(X)/Z_H(X) = (L1(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) / (n * (X - 1))
       

        // The check that p(X) = 1 at point w^{n-1}.
        //
        // Fp2(X)/Z_H(X) = (Ln(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) * w^{n-1} / (n *
        // (X - w^{n-1}))
       

        // The relation check between adjacent points on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Fp3(X) = (X - w^{n-1}) * p(X) * (1+beta) * (gamma + merged_lookup(X)) *
        // [gamma*(1+beta) + merged_table(X) + beta * merged_table(Xw)]
        //        - (X - w^{n-1}) * p(Xw) * [gamma(1+beta) + h_1(X) + beta * h_1(Xw)] *
        //          [gamma(1+beta) + h_2(X) + beta * h_2(Xw)]
        
    }

    /// Split the quotient polynomial into `num_wire_types` polynomials.
    /// The first `num_wire_types`-1 polynomials have degree `domain_size`+1.
    ///
    /// Let t(X) be the input quotient polynomial, t_i(X) be the output
    /// splitting polynomials. t(X) = \sum_{i=0}^{num_wire_types}
    /// X^{i*(n+2)} * t_i(X)
    ///
    /// NOTE: we have a step polynomial of X^(n+2) instead of X^n as in the
    /// GWC19 paper to achieve better balance among degrees of all splitting
    /// polynomials (especially the highest-degree/last one).
    /// 本质上是再把大的商多项式t(X)分割成多个小的多项式t_i(X)，这部分论文里面有，需要确认下逻辑
    fn split_quotient_polynomial<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        quot_poly: &DensePolynomial<E::ScalarField>,
        num_wire_types: usize,
    ) -> Result<Vec<DensePolynomial<E::ScalarField>>, PlonkError> {

        // compute the splitting polynomials t'_i(X) s.t. t(X) =
        // \sum_{i=0}^{num_wire_types} X^{i*(n+2)} * t'_i(X)
       

        // mask splitting polynomials t_i(X), for i in {0..num_wire_types}.
        // t_i(X) = t'_i(X) - b_last_i + b_now_i * X^(n+2)
        // with t_lowest_i(X) = t_lowest_i(X) - 0 + b_now_i * X^(n+2)
        // and t_highest_i(X) = t_highest_i(X) - b_last_i
       
        // mask the highest splitting poly
       
    }

    #[inline]
    fn mul_poly(
        poly: &DensePolynomial<E::ScalarField>,
        coeff: &E::ScalarField,
    ) -> DensePolynomial<E::ScalarField> {
        
    }
}

#[inline]
fn quotient_polynomial_degree(domain_size: usize, num_wire_types: usize) -> usize {
    num_wire_types * (domain_size + 1) + 2
}

