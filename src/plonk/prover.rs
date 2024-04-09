use core::ops::Neg;

use super::structs::{
    eval_merged_lookup_witness, eval_merged_table, Challenges, Oracles, PlookupEvaluations,
    PlookupOracles, ProofEvaluations, ProvingKey,
};
use crate::{
    constants::domain_size_ratio,
    errors::{PlonkError, SnarkError::*},
    proof_system::structs::CommitKey,
};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, One, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial, Radix2EvaluationDomain,
};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_primitives::pcs::{
    prelude::{Commitment, UnivariateKzgPCS},
    PolynomialCommitmentScheme,
};
use jf_relation::{constants::GATE_WIDTH, Arithmetization};
use jf_utils::par_utils::parallelizable_slice_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
    /// 困惑：这里domain和quot_domain到底是啥？？
    pub(crate) fn new(domain_size: usize, num_wire_types: usize) -> Result<Self, PlonkError> {
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(domain_size)
            .ok_or(PlonkError::DomainCreationError)?;
        let quot_domain = GeneralEvaluationDomain::<E::ScalarField>::new(
            domain_size * domain_size_ratio(domain_size, num_wire_types),
        )
        .ok_or(PlonkError::DomainCreationError)?;
        Ok(Self {
            domain,
            quot_domain,
        })
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
        let wire_polys: Vec<DensePolynomial<E::ScalarField>> = cs
            .compute_wire_polynomials()?
            .into_iter()
            .map(|poly| self.mask_polynomial(prng, poly, 1))
            .collect();
        /// 接受密钥和多项式，返回多项式的承诺
        let wires_poly_comms = UnivariateKzgPCS::batch_commit(ck, &wire_polys)?;
        /// 用constraint system当中实现的计算公共输入多项式的方法直接得到公共输入多项式
        let pub_input_poly = cs.compute_pub_input_polynomial()?;
        /// 返回wire witness polynomials和他们的承诺，以及公共输入多项式
        Ok(((wires_poly_comms, wire_polys), pub_input_poly))
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
        let prod_perm_poly = self.mask_polynomial(
            prng,
            /// 通过调用cs当中定义好的直接算乘积置换的多项式
            cs.compute_prod_permutation_polynomial(&challenges.beta, &challenges.gamma)?,
            2,
        );
        /// 得到乘积置换多项式的承诺
        let prod_perm_comm = UnivariateKzgPCS::commit(ck, &prod_perm_poly)?;
        /// 返回乘积置换多项式和它的commitment
        Ok((prod_perm_comm, prod_perm_poly))
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
        let quot_poly =
            self.compute_quotient_polynomial(challenges, pks, online_oracles, num_wire_types)?;
        /// 将商多项式分割成为多个多项式
        let split_quot_polys = self.split_quotient_polynomial(prng, &quot_poly, num_wire_types)?;
        /// 计算分割之后的多项式的承诺
        let split_quot_poly_comms = UnivariateKzgPCS::batch_commit(ck, &split_quot_polys)?;
        /// 返回分割之后的多项式和他们的承诺
        Ok((split_quot_poly_comms, split_quot_polys))
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
        let wires_evals: Vec<E::ScalarField> =
            parallelizable_slice_iter(&online_oracles.wire_polys)
                .map(|poly| poly.evaluate(&challenges.zeta))
                .collect();
        /// 计算了pk.sigmas中的每个多项式在challenges.zeta点的评估值，并将结果收集到一个向量中。
        let wire_sigma_evals: Vec<E::ScalarField> = parallelizable_slice_iter(&pk.sigmas)
            .take(num_wire_types - 1)
            .map(|poly| poly.evaluate(&challenges.zeta))
            .collect();
        /// 计算了online_oracles.prod_perm_poly在challenges.zeta点的评估值
        let perm_next_eval = online_oracles
            .prod_perm_poly
            .evaluate(&(challenges.zeta * self.domain.group_gen));

        ProofEvaluations {
            wires_evals,
            wire_sigma_evals,
            perm_next_eval,
        }
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
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing opening proofs".to_string(),
            )
            .into());
        }
        // List the polynomials to be opened at point `zeta`.
        let mut polys_ref = vec![lin_poly];
        for (pk, oracles) in pks.iter().zip(online_oracles.iter()) {
            for poly in oracles.wire_polys.iter() {
                polys_ref.push(poly);
            }
            // Note we do not add the last wire sigma polynomial.
            for poly in pk.sigmas.iter().take(pk.sigmas.len() - 1) {
                polys_ref.push(poly);
            }

            // Add Plookup related polynomials if support lookup.
            let lookup_flag =
                pk.plookup_pk.is_some() && (oracles.plookup_oracles.h_polys.len() == 2);
            if lookup_flag {
                polys_ref.extend(Self::plookup_open_polys_ref(oracles, pk)?);
            }
        }

        let opening_proof =
            Self::compute_batched_witness_polynomial_commitment(ck, &polys_ref, v, zeta)?;

        // List the polynomials to be opened at point `zeta * w`.
        let mut polys_ref = vec![];
        for (pk, oracles) in pks.iter().zip(online_oracles.iter()) {
            polys_ref.push(&oracles.prod_perm_poly);
            // Add Plookup related polynomials if support lookup
            let lookup_flag =
                pk.plookup_pk.is_some() && (oracles.plookup_oracles.h_polys.len() == 2);
            if lookup_flag {
                polys_ref.extend(Self::plookup_shifted_open_polys_ref(oracles, pk)?);
            }
        }

        let shifted_opening_proof = Self::compute_batched_witness_polynomial_commitment(
            ck,
            &polys_ref,
            v,
            &(self.domain.group_gen * zeta),
        )?;

        Ok((opening_proof, shifted_opening_proof))
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
        let mask_poly =
            DensePolynomial::rand(hiding_bound, prng).mul_by_vanishing_poly(self.domain);
        mask_poly + poly
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
        let (batch_poly, _) = polys_ref.iter().fold(
            (DensePolynomial::zero(), E::ScalarField::one()),
            |(acc, coeff), &poly| (acc + Self::mul_poly(poly, &coeff), coeff * r),
        );

        // Compute opening witness polynomial and its commitment
        let divisor =
            DensePolynomial::from_coefficients_vec(vec![-*eval_point, E::ScalarField::one()]);
        let witness_poly = &batch_poly / &divisor;

        UnivariateKzgPCS::commit(ck, &witness_poly).map_err(PlonkError::PCSError)
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
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing quotient polys".to_string(),
            )
            .into());
        }

        let n = self.domain.size();
        let m = self.quot_domain.size();
        let domain_size_ratio = m / n;
        // Compute 1/Z_H(w^i).
        let z_h_inv: Vec<E::ScalarField> = (0..domain_size_ratio)
            .map(|i| {
                ((E::ScalarField::GENERATOR * self.quot_domain.element(i)).pow([n as u64])
                    - E::ScalarField::one())
                .inverse()
                .unwrap()
            })
            .collect();

        // Compute coset evaluations of the quotient polynomial.
        let mut quot_poly_coset_evals_sum = vec![E::ScalarField::zero(); m];
        let mut alpha_base = E::ScalarField::one();
        let alpha_3 = challenges.alpha.square() * challenges.alpha;
        let alpha_7 = alpha_3.square() * challenges.alpha;
        // TODO: figure out if the unwrap is safe/map error?
        let coset = self
            .quot_domain
            .get_coset(E::ScalarField::GENERATOR)
            .unwrap();
        // enumerate proving instances
        for (oracles, pk) in online_oracles.iter().zip(pks.iter()) {
            // lookup_flag = 1 if support Plookup argument.
            let lookup_flag = pk.plookup_pk.is_some();

            // Compute coset evaluations.
            let selectors_coset_fft: Vec<Vec<E::ScalarField>> =
                parallelizable_slice_iter(&pk.selectors)
                    .map(|poly| coset.fft(poly.coeffs()))
                    .collect();
            let sigmas_coset_fft: Vec<Vec<E::ScalarField>> = parallelizable_slice_iter(&pk.sigmas)
                .map(|poly| coset.fft(poly.coeffs()))
                .collect();
            let wire_polys_coset_fft: Vec<Vec<E::ScalarField>> =
                parallelizable_slice_iter(&oracles.wire_polys)
                    .map(|poly| coset.fft(poly.coeffs()))
                    .collect();

            // TODO: (binyi) we can also compute below in parallel with
            // `wire_polys_coset_fft`.
            let prod_perm_poly_coset_fft = coset.fft(oracles.prod_perm_poly.coeffs());
            let pub_input_poly_coset_fft = coset.fft(oracles.pub_inp_poly.coeffs());

            // Compute coset evaluations of Plookup online oracles.
            let (
                table_dom_sep_coset_fft,
                q_dom_sep_coset_fft,
                range_table_coset_fft,
                key_table_coset_fft,
                h_coset_ffts,
                prod_lookup_poly_coset_fft,
            ) = if lookup_flag {
                let table_dom_sep_coset_fft =
                    coset.fft(pk.plookup_pk.as_ref().unwrap().table_dom_sep_poly.coeffs());
                let q_dom_sep_coset_fft =
                    coset.fft(pk.plookup_pk.as_ref().unwrap().q_dom_sep_poly.coeffs());
                let range_table_coset_fft =
                    coset.fft(pk.plookup_pk.as_ref().unwrap().range_table_poly.coeffs()); // safe unwrap
                let key_table_coset_fft =
                    coset.fft(pk.plookup_pk.as_ref().unwrap().key_table_poly.coeffs()); // safe unwrap
                let h_coset_ffts: Vec<Vec<E::ScalarField>> =
                    parallelizable_slice_iter(&oracles.plookup_oracles.h_polys)
                        .map(|poly| coset.fft(poly.coeffs()))
                        .collect();
                let prod_lookup_poly_coset_fft =
                    coset.fft(oracles.plookup_oracles.prod_lookup_poly.coeffs());
                (
                    Some(table_dom_sep_coset_fft),
                    Some(q_dom_sep_coset_fft),
                    Some(range_table_coset_fft),
                    Some(key_table_coset_fft),
                    Some(h_coset_ffts),
                    Some(prod_lookup_poly_coset_fft),
                )
            } else {
                (None, None, None, None, None, None)
            };

            // Compute coset evaluations of the quotient polynomial.
            let quot_poly_coset_evals: Vec<E::ScalarField> =
                parallelizable_slice_iter(&(0..m).collect::<Vec<_>>())
                    .map(|&i| {
                        let w: Vec<E::ScalarField> = (0..num_wire_types)
                            .map(|j| wire_polys_coset_fft[j][i])
                            .collect();
                        let w_next: Vec<E::ScalarField> = (0..num_wire_types)
                            .map(|j| wire_polys_coset_fft[j][(i + domain_size_ratio) % m])
                            .collect();

                        let t_circ = Self::compute_quotient_circuit_contribution(
                            i,
                            &w,
                            &pub_input_poly_coset_fft[i],
                            &selectors_coset_fft,
                        );
                        let (t_perm_1, t_perm_2) =
                            Self::compute_quotient_copy_constraint_contribution(
                                i,
                                self.quot_domain.element(i) * E::ScalarField::GENERATOR,
                                pk,
                                &w,
                                &prod_perm_poly_coset_fft[i],
                                &prod_perm_poly_coset_fft[(i + domain_size_ratio) % m],
                                challenges,
                                &sigmas_coset_fft,
                            );
                        let mut t1 = t_circ + t_perm_1;
                        let mut t2 = t_perm_2;

                        // add Plookup-related terms
                        if lookup_flag {
                            let (t_lookup_1, t_lookup_2) = self
                                .compute_quotient_plookup_contribution(
                                    i,
                                    self.quot_domain.element(i) * E::ScalarField::GENERATOR,
                                    pk,
                                    &w,
                                    &w_next,
                                    h_coset_ffts.as_ref().unwrap(),
                                    prod_lookup_poly_coset_fft.as_ref().unwrap(),
                                    range_table_coset_fft.as_ref().unwrap(),
                                    key_table_coset_fft.as_ref().unwrap(),
                                    selectors_coset_fft.last().unwrap(), /* TODO: add a method
                                                                          * to extract
                                                                          * q_lookup_coset_fft */
                                    table_dom_sep_coset_fft.as_ref().unwrap(),
                                    q_dom_sep_coset_fft.as_ref().unwrap(),
                                    challenges,
                                );
                            t1 += t_lookup_1;
                            t2 += t_lookup_2;
                        }
                        t1 * z_h_inv[i % domain_size_ratio] + t2
                    })
                    .collect();

            for (a, b) in quot_poly_coset_evals_sum
                .iter_mut()
                .zip(quot_poly_coset_evals.iter())
            {
                *a += alpha_base * b;
            }
            // update the random combiner for aggregating multiple proving instances
            if lookup_flag {
                alpha_base *= alpha_7;
            } else {
                alpha_base *= alpha_3;
            }
        }
        // Compute the coefficient form of the quotient polynomial
        Ok(DensePolynomial::from_coefficients_vec(
            coset.ifft(&quot_poly_coset_evals_sum),
        ))
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
        // TODO: (binyi) get the order from a function.
        let q_lc: Vec<E::ScalarField> =
            (0..GATE_WIDTH).map(|j| selectors_coset_fft[j][i]).collect();
        let q_mul: Vec<E::ScalarField> = (GATE_WIDTH..GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_hash: Vec<E::ScalarField> = (GATE_WIDTH + 2..2 * GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_o = selectors_coset_fft[2 * GATE_WIDTH + 2][i];
        let q_c = selectors_coset_fft[2 * GATE_WIDTH + 3][i];
        let q_ecc = selectors_coset_fft[2 * GATE_WIDTH + 4][i];

        q_c + pi
            + q_lc[0] * w[0]
            + q_lc[1] * w[1]
            + q_lc[2] * w[2]
            + q_lc[3] * w[3]
            + q_mul[0] * w[0] * w[1]
            + q_mul[1] * w[2] * w[3]
            + q_ecc * w[0] * w[1] * w[2] * w[3] * w[4]
            + q_hash[0] * w[0].pow([5])
            + q_hash[1] * w[1].pow([5])
            + q_hash[2] * w[2].pow([5])
            + q_hash[3] * w[3].pow([5])
            - q_o * w[4]
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
        let num_wire_types = w.len();
        let n = pk.domain_size();

        // The check that:
        //   \prod_i [w_i(X) + beta * k_i * X + gamma] * z(X)
        // - \prod_i [w_i(X) + beta * sigma_i(X) + gamma] * z(wX) = 0
        // on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Extended permutation values
        let sigmas: Vec<E::ScalarField> = (0..num_wire_types)
            .map(|j| sigmas_coset_fft[j][i])
            .collect();

        // Compute the 1st term.
        let mut result_1 = challenges.alpha
            * w.iter().enumerate().fold(*z_x, |acc, (j, &w)| {
                acc * (w + pk.k()[j] * eval_point * challenges.beta + challenges.gamma)
            });
        // Minus the 2nd term.
        result_1 -= challenges.alpha
            * w.iter()
                .zip(sigmas.iter())
                .fold(*z_xw, |acc, (&w, &sigma)| {
                    acc * (w + sigma * challenges.beta + challenges.gamma)
                });

        // The check that z(x) = 1 at point 1.
        // (z(x)-1) * L1(x) * alpha^2 / Z_H(x) = (z(x)-1) * alpha^2 / (n * (x - 1))
        let result_2 = challenges.alpha.square() * (*z_x - E::ScalarField::one())
            / (E::ScalarField::from(n as u64) * (eval_point - E::ScalarField::one()));

        (result_1, result_2)
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
        assert!(pk.plookup_pk.is_some());
        assert_eq!(h_coset_ffts.len(), 2);

        let n = pk.domain_size();
        let m = self.quot_domain.size();
        let domain_size_ratio = m / n;
        let n_field = E::ScalarField::from(n as u64);
        let lagrange_n_coeff =
            self.domain.group_gen_inv / (n_field * (eval_point - self.domain.group_gen_inv));
        let lagrange_1_coeff =
            E::ScalarField::one() / (n_field * (eval_point - E::ScalarField::one()));
        let mut alpha_power = challenges.alpha * challenges.alpha * challenges.alpha;

        // extract polynomial evaluations
        let h_1_x = h_coset_ffts[0][i];
        let h_1_xw = h_coset_ffts[0][(i + domain_size_ratio) % m];
        let h_2_x = h_coset_ffts[1][i];
        let h_2_xw = h_coset_ffts[1][(i + domain_size_ratio) % m];
        let p_x = prod_lookup_coset_fft[i];
        let p_xw = prod_lookup_coset_fft[(i + domain_size_ratio) % m];
        let range_table_x = range_table_coset_fft[i];
        let key_table_x = key_table_coset_fft[i];
        let table_dom_sep_x = table_dom_sep_coset_fft[i];
        let q_dom_sep_x = q_dom_sep_coset_fft[i];

        let range_table_xw = range_table_coset_fft[(i + domain_size_ratio) % m];
        let key_table_xw = key_table_coset_fft[(i + domain_size_ratio) % m];
        let table_dom_sep_xw = table_dom_sep_coset_fft[(i + domain_size_ratio) % m];
        let merged_table_x = eval_merged_table::<E>(
            challenges.tau,
            range_table_x,
            key_table_x,
            q_lookup_coset_fft[i],
            w[3],
            w[4],
            table_dom_sep_x,
        );
        let merged_table_xw = eval_merged_table::<E>(
            challenges.tau,
            range_table_xw,
            key_table_xw,
            q_lookup_coset_fft[(i + domain_size_ratio) % m],
            w_next[3],
            w_next[4],
            table_dom_sep_xw,
        );
        let merged_lookup_x = eval_merged_lookup_witness::<E>(
            challenges.tau,
            w[5],
            w[0],
            w[1],
            w[2],
            q_lookup_coset_fft[i],
            q_dom_sep_x,
        );

        // The check that h1(X) - h2(wX) = 0 at point w^{n-1}
        //
        // Fh(X)/Z_H(X) = (Ln(X) * (h1(X) - h2(wX))) / Z_H(X) = (h1(X) - h2(wX)) *
        // w^{n-1} / (n * (X - w^{n-1}))
        let term_h = (h_1_x - h_2_xw) * lagrange_n_coeff;
        let mut result_2 = alpha_power * term_h;
        alpha_power *= challenges.alpha;

        // The check that p(X) = 1 at point 1.
        //
        // Fp1(X)/Z_H(X) = (L1(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) / (n * (X - 1))
        let term_p_1 = (p_x - E::ScalarField::one()) * lagrange_1_coeff;
        result_2 += alpha_power * term_p_1;
        alpha_power *= challenges.alpha;

        // The check that p(X) = 1 at point w^{n-1}.
        //
        // Fp2(X)/Z_H(X) = (Ln(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) * w^{n-1} / (n *
        // (X - w^{n-1}))
        let term_p_2 = (p_x - E::ScalarField::one()) * lagrange_n_coeff;
        result_2 += alpha_power * term_p_2;
        alpha_power *= challenges.alpha;

        // The relation check between adjacent points on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Fp3(X) = (X - w^{n-1}) * p(X) * (1+beta) * (gamma + merged_lookup(X)) *
        // [gamma*(1+beta) + merged_table(X) + beta * merged_table(Xw)]
        //        - (X - w^{n-1}) * p(Xw) * [gamma(1+beta) + h_1(X) + beta * h_1(Xw)] *
        //          [gamma(1+beta) + h_2(X) + beta * h_2(Xw)]
        let beta_plus_one = E::ScalarField::one() + challenges.beta;
        let gamma_mul_beta_plus_one = beta_plus_one * challenges.gamma;
        let term_p_3 = (eval_point - self.domain.group_gen_inv)
            * (p_x
                * beta_plus_one
                * (challenges.gamma + merged_lookup_x)
                * (gamma_mul_beta_plus_one + merged_table_x + challenges.beta * merged_table_xw)
                - p_xw
                    * (gamma_mul_beta_plus_one + h_1_x + challenges.beta * h_1_xw)
                    * (gamma_mul_beta_plus_one + h_2_x + challenges.beta * h_2_xw));
        let result_1 = alpha_power * term_p_3;

        (result_1, result_2)
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
        let expected_degree = quotient_polynomial_degree(self.domain.size(), num_wire_types);
        if quot_poly.degree() != expected_degree {
            return Err(WrongQuotientPolyDegree(quot_poly.degree(), expected_degree).into());
        }
        let n = self.domain.size();
        // compute the splitting polynomials t'_i(X) s.t. t(X) =
        // \sum_{i=0}^{num_wire_types} X^{i*(n+2)} * t'_i(X)
        let mut split_quot_polys: Vec<DensePolynomial<E::ScalarField>> =
            parallelizable_slice_iter(&(0..num_wire_types).collect::<Vec<_>>())
                .map(|&i| {
                    let end = if i < num_wire_types - 1 {
                        (i + 1) * (n + 2)
                    } else {
                        quot_poly.degree() + 1
                    };
                    // Degree-(n+1) polynomial has n + 2 coefficients.
                    DensePolynomial::<E::ScalarField>::from_coefficients_slice(
                        &quot_poly.coeffs[i * (n + 2)..end],
                    )
                })
                .collect();

        // mask splitting polynomials t_i(X), for i in {0..num_wire_types}.
        // t_i(X) = t'_i(X) - b_last_i + b_now_i * X^(n+2)
        // with t_lowest_i(X) = t_lowest_i(X) - 0 + b_now_i * X^(n+2)
        // and t_highest_i(X) = t_highest_i(X) - b_last_i
        let mut last_randomizer = E::ScalarField::zero();
        split_quot_polys
            .iter_mut()
            .take(num_wire_types - 1)
            .for_each(|poly| {
                let now_randomizer = E::ScalarField::rand(prng);

                poly.coeffs[0] -= last_randomizer;
                assert_eq!(poly.degree(), n + 1);
                poly.coeffs.push(now_randomizer);

                last_randomizer = now_randomizer;
            });
        // mask the highest splitting poly
        split_quot_polys[num_wire_types - 1].coeffs[0] -= last_randomizer;

        Ok(split_quot_polys)
    }

    #[inline]
    fn mul_poly(
        poly: &DensePolynomial<E::ScalarField>,
        coeff: &E::ScalarField,
    ) -> DensePolynomial<E::ScalarField> {
        DensePolynomial::<E::ScalarField>::from_coefficients_vec(
            parallelizable_slice_iter(&poly.coeffs)
                .map(|c| *coeff * c)
                .collect(),
        )
    }
}

#[inline]
fn quotient_polynomial_degree(domain_size: usize, num_wire_types: usize) -> usize {
    num_wire_types * (domain_size + 1) + 2
}

