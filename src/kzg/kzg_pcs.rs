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

    }

    /// Generate a commitment for a list of polynomials
    /// 这里的这个batch是直接用了jf_utils::par_utils::parallelizable_slice_iter;这个函数
    /// 这个函数是用来创建一个可以并行处理的切片迭代器。这意味着polys中的每个多项式可以在不同的线程上并行处理。
    fn batch_commit(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError> {

    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    /// 这一步本质上在做prove an evaluation的事情
    /// 即打开一个点phi(a) = b, 然后算quotient polynomial = (phi(x) - b)/ (x - a)
    /// proof本质上是在求pi = g1^q(tau), 就是quotient polynomial的commitment
    /// 入参中，prover_param是prover的参数，polynomial是多项式，point是要打开的点a
    /// 返回值是一个元组，包含了proof（对quotient polynomial的commitment）和evaluation的值b
    fn open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
       
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
       
    }

}