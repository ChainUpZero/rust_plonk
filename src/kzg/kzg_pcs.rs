// use crate::{
//     pcs::{
//         poly::GeneralDensePolynomial, prelude::Commitment, PCSError, PolynomialCommitmentScheme,
//         StructuredReferenceString, UnivariatePCS,
//     },
//     toeplitz::ToeplitzMatrix,
// };
// use ark_ec::{
//     pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
// };
// use ark_ff::{FftField, Field, PrimeField};
// #[cfg(not(feature = "seq-fk-23"))]
// use ark_poly::EvaluationDomain;
// use ark_poly::{
//     univariate::DensePolynomial, DenseUVPolynomial, Polynomial, Radix2EvaluationDomain,
// };
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::{
//     borrow::Borrow,
//     end_timer, format,
//     marker::PhantomData,
//     ops::Mul,
//     rand::{CryptoRng, RngCore},
//     start_timer,
//     string::ToString,
//     vec,
//     vec::Vec,
//     One, UniformRand, Zero,
// };
// use jf_utils::par_utils::parallelizable_slice_iter;
// #[cfg(feature = "parallel")]
// use rayon::prelude::*;
// use srs::{UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam};

///需要check的引用：
/// 1. derive(Derivative不知道哪来的，看起来像是直接引入的叫做derivative的包，待确认
/// 2. #[derivative(Hash)]看起来像是Derivative包里面的，待确认


pub(crate) mod srs;

/// KZG Polynomial Commitment Scheme on univariate polynomial.
pub struct UnivariateKzgPCS<E> {
    #[doc(hidden)]
    /// PhantomData是Rust的一个标准库类型，用于表示某种数据的"幽灵"或"虚假"存在。
    phantom: PhantomData<E>,
}


#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
#[derivative(Hash)]
/// proof of opening
/// 本质上是在求pi = g1^q(tau), 就是quotient polynomial的commitment
pub struct UnivariateKzgProof<E: Pairing> {
    /// Evaluation of quotients
    pub proof: E::G1Affine,
}
/// batch proof
pub type UnivariateKzgBatchProof<E> = Vec<UnivariateKzgProof<E>>;

/// 这里实现了完整的PolynomialCommitmentScheme
impl<E: Pairing> PolynomialCommitmentScheme for UnivariateKzgPCS<E> {
    // Config
    type SRS = UnivariateUniversalParams<E>;
    // Polynomial and its associated types
    type Polynomial = DensePolynomial<E::ScalarField>;
    type Point = E::ScalarField;
    type Evaluation = E::ScalarField;
    // Polynomial and its associated types
    type Commitment = Commitment<E>;
    type BatchCommitment = Vec<Self::Commitment>;
    type Proof = UnivariateKzgProof<E>;
    type BatchProof = UnivariateKzgBatchProof<E>;

    /// Trim the universal parameters to specialize the public parameters.
    /// Input `max_degree` for univariate.
    /// `supported_num_vars` must be None or an error is returned.
    /// 本质上是根据supported_degree来从srs中获取适合当前degree的prover和verifier的参数，要求supported_num_vars是None
    /// 如果成功执行，则返回一个元组，包含prover和verifier的参数。
    /// 如果失败（supported_num_vars是some），则返回一个错误。
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<(UnivariateProverParam<E>, UnivariateVerifierParam<E>), PCSError> {
        /// supported_num_vars是一个Option<usize>类型的值。
        /// 如果supported_num_vars是Some，那么它包含一个usize类型的值。
        /// 如果supported_num_vars是None，那么它不包含任何值。
        if supported_num_vars.is_some() {
            return Err(PCSError::InvalidParameters(
                "univariate should not receive a num_var param".to_string(),
            ));
        }
        srs.borrow().trim(supported_degree)
    }

    /// Generate a commitment for a polynomial
    /// Note that the scheme is not hiding
    /// 这里本质上实现了commit一个多项式：c = g^Phi(tau)
    fn commit(
        /// Borrow trait是Rust标准库中的一个trait，它用于借用一个值。
        /// 如果一个类型实现了Borrow<T> trait，那么它可以被看作是T类型的引用。
        /// 这通常用于允许函数接受一个值的所有权或者只借用该值。
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();

        #[cfg(feature = "kzg-print-trace")]
        let commit_time =
            start_timer!(|| format!("Committing to polynomial of degree {} ", poly.degree()));

        /// 检查一下当前的poly的degree没有超过pk能容纳的最大degree的大小
        if poly.degree() > prover_param.powers_of_g.len() {
            return Err(PCSError::InvalidParameters(format!(
                "poly degree {} is larger than allowed {}",
                poly.degree(),
                prover_param.powers_of_g.len()
            )));
        }

        /// 利用后面自己定义好的skip_leading_zeros_and_convert_to_bigints函数对poly格式进行处理
        /// 处理称为前面有几个0和coefficients的集合的形式
        /// 其中这个poly的格式其实是ark_poly这个包当中定义好的
        let (num_leading_zeros, plain_coeffs) = skip_leading_zeros_and_convert_to_bigints(poly);

        /// 这是一个条件编译指令，它表示下一行代码只有在kzg-print-trace特性被启用时才会编译和执行。
        #[cfg(feature = "kzg-print-trace")]
        let msm_time = start_timer!(|| "MSM to compute commitment to plaintext
        poly");

        /// 算commitment本质上就是把系数coefficients和g的幂次方（部分pk）进行线性组合
        /// 所以入参就是截断了一部分的额pk和coefficients
        /// msm_bigint可以用来算commitment
        /// 函数还没找到，但是估计实现就是两个vec每一项做点的乘法，然后把每一项的结果加起来
        /// into_affine()函数就是用来将点从射影坐标转换为仿射坐标的。
        /// 仿射坐标：每个点由两个坐标(x, y)表示
        /// 射影坐标：每个点由三个坐标(x, y, z)表示，其中x = X/Z和y = Y/Z
        /// 射影坐标可以更有效地进行某些计算，特别是点的加法和倍乘，因为它们可以避免进行昂贵的字段除法操作
        let commitment = E::G1::msm_bigint(
            &prover_param.powers_of_g[num_leading_zeros..],
            &plain_coeffs,
        )
        .into_affine();

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(msm_time);
        #[cfg(feature = "kzg-print-trace")]
        end_timer!(commit_time);
        Ok(Commitment(commitment))
    }

    /// Generate a commitment for a list of polynomials
    /// 这里的这个batch是直接用了jf_utils::par_utils::parallelizable_slice_iter;这个函数
    /// 这个函数是用来创建一个可以并行处理的切片迭代器。这意味着polys中的每个多项式可以在不同的线程上并行处理。
    fn batch_commit(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_time = start_timer!(|| format!("batch commit {} polynomials", polys.len()));
        /// parallelizable_slice_iter(polys)：这个函数可能是用来创建一个可以并行处理的切片迭代器。这意味着polys中的每个多项式可以在不同的线程上并行处理。
        /// map(|poly| Self::commit(prover_param, poly))：这个函数是对polys中的每个多项式进行commit操作。
        /// collect::<Result<Vec<Self::Commitment>, PCSError>>()?：这个函数是将所有的commit结果收集到一个Vec中。
        /// let res = ...?;：这个语句将结果赋值给res变量。如果collect函数返回一个错误，那么?操作符将立即从当前函数返回这个错误。
        let res = parallelizable_slice_iter(polys)
            .map(|poly| Self::commit(prover_param, poly))
            .collect::<Result<Vec<Self::Commitment>, PCSError>>()?;

        end_timer!(commit_time);
        Ok(res)
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    /// 这一步本质上在做prove an evaluation的事情
    /// 即打开一个点phi(a) = b, 然后算quotient polynomial = (phi(x) - b)/ (x - a)
    /// proof本质上是在求pi = g1^q(tau), 就是quotient polynomial的commitment
    /// 入参中，prover_param是prover的参数，polynomial是多项式，point是要打开的点a
    /// 返回值是一个元组，包含了proof（对quotient polynomial的commitment）和evaluation的值b
    /// ！！！不过这里很奇怪，算quotient polynomial的时候，分子部分没有减去evaluation的值，不确定发生了什么
    fn open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        #[cfg(feature = "kzg-print-trace")]
        let open_time =
            start_timer!(|| format!("Opening polynomial of degree {}", polynomial.degree()));
        
        /// 这里的divisor是一个多项式，它的系数是[-point, 1]，即(x - point)
        let divisor = Self::Polynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);

        #[cfg(feature = "kzg-print-trace")]
        let witness_time = start_timer!(|| "Computing witness polynomial");

        /// 很奇怪，为什么这里的polynomial 不需要减去evaluation的值
        /// 理论上来说，算quotient poly的逻辑就是(polynomial - evaluation)/(x-point)
        let witness_polynomial = polynomial / &divisor;

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(witness_time);

        /// 这里复用前面的逻辑，用来处理witness_polynomial
        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);
        
        /// 这里复用前面的逻辑，直接用现成实现好的msm_bigint来计算commitment
        let proof: E::G1Affine = E::G1::msm_bigint(
            &prover_param.borrow().powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        )
        .into_affine();

        // TODO offer an `open()` that doesn't also evaluate
        // https://github.com/EspressoSystems/jellyfish/issues/426
        let eval = polynomial.evaluate(point);

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(open_time);

        Ok((Self::Proof { proof }, eval))
    }

    /// Input a list of polynomials, and a same number of points,
    /// compute a multi-opening for all the polynomials.
    // This is a naive approach
    // TODO: to implement the more efficient batch opening algorithm
    // (e.g., the appendix C.4 in https://eprint.iacr.org/2020/1536.pdf)
    /// 这里的batch_open是对多个多项式在多个点上进行open操作
    /// 入参中，prover_param是prover的参数，multi_commitment是多项式的commitment，polynomials是多项式的集合，points是点的集合
    /// (其中，在Rust中，函数参数的名称如果以_开头，通常表示这个参数在函数体中没有被使用)
    /// 返回值是一个元组，里面是两个vec，一个是proof的集合，一个是evaluation的集合
    fn batch_open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        _multi_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        let open_time = start_timer!(|| format!("batch opening {} polynomials", polynomials.len()));
        if polynomials.len() != points.len() {
            return Err(PCSError::InvalidParameters(format!(
                "poly length {} is different from points length {}",
                polynomials.len(),
                points.len()
            )));
        }
        let mut batch_proof = vec![];
        let mut evals = vec![];
        /// zip()方法则会将两个迭代器合并成一个新的迭代器，新的迭代器的每一个元素都是一个元组，元组中的元素分别来自于原来的两个迭代器。
        for (poly, point) in polynomials.iter().zip(points.iter()) {
            let (proof, eval) = Self::open(prover_param.borrow(), poly, point)?;
            batch_proof.push(proof);
            evals.push(eval);
        }

        end_timer!(open_time);
        Ok((batch_proof, evals))
    }
    
    
    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    /// 这里本质上在做verify an evaluation的事情
    /// 目的是验证phi(tau)-b = q(tau) * (tau-a)
    /// 用bilinear pairing的话等价于e(g1,g2)^(phi(tau)-b) = e(g1,g2)^(q(tau)*(tau-a))
    /// 也就是e(com-g1^b,g2) = e(pi,vk-g2^a)
    /// 这里实现上其实是一样的，只是吧g2^a移到了左边做，所以强烈怀疑算quotient poly的时候错了
    fn verify(
        verifier_param: &UnivariateVerifierParam<E>,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let check_time = start_timer!(|| "Checking evaluation");
        ///这里算的是[g1^b-pi^a-com, pi]
        ///commitment.0.into_group()指的是commitment的第一个字段转换为一个群元素
        let pairing_inputs_l: Vec<E::G1Prepared> = vec![
            (verifier_param.g * value - proof.proof * point - commitment.0.into_group())
                .into_affine()
                .into(),
            proof.proof.into(),
        ];
        /// 这里算的是[g2, vk]
        let pairing_inputs_r: Vec<E::G2Prepared> =
            vec![verifier_param.h.into(), verifier_param.beta_h.into()];

        /// 返回multi_pairing方法返回的元组或结构体的第一个字段。在这个上下文中，这可能是配对操作的结果。
        /// .is_one()检查了这个结果是否为1。在密码学中，检查配对的结果是否为1通常用于验证某些性质，例如在零知识证明中验证证明的正确性。
        /// res是一个布尔值，如果配对的结果为1，那么res为true，否则为false。
        let res = E::multi_pairing(pairing_inputs_l, pairing_inputs_r)
            .0
            .is_one();

        end_timer!(check_time, || format!("Result: {res}"));
        Ok(res)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    // This is a naive approach
    // TODO: to implement the more efficient batch verification algorithm
    // (e.g., the appendix C.4 in https://eprint.iacr.org/2020/1536.pdf)
    // 本质上就是把多个多项式用随机生成的系数连在一起，成为一个大的多项式，然后用一次验证batch多次verify
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &UnivariateVerifierParam<E>,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        rng: &mut R,
    ) -> Result<bool, PCSError> {
        let check_time =
            start_timer!(|| format!("Checking {} evaluation proofs", multi_commitment.len()));
        
        /// zero方法返回这个群的零元素，也就是这个群的单位元素
        let mut total_c = <E::G1>::zero();
        let mut total_w = <E::G1>::zero();

        let combination_time = start_timer!(|| "Combining commitments and proofs");
        let mut randomizer = E::ScalarField::one();
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::ScalarField::zero();
        for (((c, z), v), proof) in multi_commitment
            .iter()
            .zip(points)
            .zip(values)
            .zip(batch_proof)
        {
            let w = proof.proof;
            /// pi^a
            let mut temp = w.mul(*z);
            /// temp = pi^a + com
            temp += &c.0;
            /// c = temp = pi^a + com
            let c = temp;
            /// g_multiplier = b + 随机数^b + 另一个随机数^b + ...
            g_multiplier += &(randomizer * v);
            /// total_c = total_c + c * 随机数 + c * 另一个随机数 + ...
            total_c += c * randomizer;
            /// total_w = pi + pi * 随机数 + pi * 另一个随机数 + ...
            total_w += w * randomizer;
            // We don't need to sample randomizers from the full field,
            // only from 128-bit strings.
            randomizer = u128::rand(rng).into();
        }
        /// total_c = total_c - g^b - g^随机数^b - g^另一个随机数^b - ...
        /// = total_c + c * 随机数 + c * 另一个随机数 + ... - g^b - g^随机数^b - g^另一个随机数^b - ...
        /// = pi^a + com + pi^a * 随机数 + com * 随机数 + pi^a * 另一个随机数 + com * 另一个随机数 + ... - g^b - g^随机数^b - g^另一个随机数^b - ...
        /// =(pi^a + com - g^b) +(pi^a * 随机数 + com * 随机数-g^b*随机数) + (pi^a * 另一个随机数 + com * 另一个随机数 - g^b * 另一个随机数) + ...
        total_c -= &verifier_param.g.mul(g_multiplier);
        end_timer!(combination_time);

        let to_affine_time = start_timer!(|| "Converting results to affine for pairing");
        let affine_points = E::G1::normalize_batch(&[-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);
        end_timer!(to_affine_time);

        let pairing_time = start_timer!(|| "Performing product of pairings");
        let result = E::multi_pairing(
            [total_w, total_c],
            [verifier_param.beta_h, verifier_param.h],
        )
        .0
        .is_one();
        end_timer!(pairing_time);
        end_timer!(check_time, || format!("Result: {result}"));
        Ok(result)
    }

}