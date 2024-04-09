use crate::pcs::{PCSError, StructuredReferenceString};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};

#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Default)]
// 这个结构体包含了 KZG10 方案的通用参数
// 主要在做的事情是kzg的setup
pub struct UnivariateUniversalParams<E: Pairing> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`.
    // 这里在做的事情是生成pk，即pk = { g1, g1^tau, g1^tau^2, ..., g1^tau^degree }
    pub powers_of_g: Vec<E::G1Affine>,
    /// TODO: remove h and beta_h
    /// The generator of G2.
    // 相当于G2 的生成元:g2
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    // 这里在做的事情是生成vk,即vk = g2^tau
    pub beta_h: E::G2Affine,
    /// powers of \beta time the generator h of G2
    // 这里不太清楚在干啥，看起来像是生成了另一个pk, 即pk = { g2, g2^tau, g2^tau^2, ..., g2^tau^degree }
    pub powers_of_h: Vec<E::G2Affine>,
}

// 这里直接通过算vector的长度来获取kzg最大支持commit的degree l
impl<E: Pairing> UnivariateUniversalParams<E> {
    /// Returns the maximum supported degree
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `UnivariateProverParam` is used to generate a proof
/// 对于prover来说，这个结构体负责生成对polynomial的commitment，即生成c = g1^Phi(tau)
/// 以及生成prove an evaluation的pi, pi指的是打开一个点random的点a之后，得到的quotient poly的commitment
/// 这里的这个commitment本质上是椭圆曲线上的一个点
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct UnivariateProverParam<E: Pairing> {
    /// Config
    pub powers_of_g: Vec<E::G1Affine>,
}

#[derive(Derivative, Clone, Debug, Eq, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
#[derivative(Default)]
// 本质上就是universal的参数
pub struct UnivariateVerifierParam<E: Pairing> {
    /// TODO: remove g, h and beta_h
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// powers of \beta time the generator h of G2: only used for multi-point
    /// openings
    pub powers_of_h: Vec<E::G2Affine>,
    /// powers of \beta time the generator g of G1: only used for multi-point
    /// openings
    pub powers_of_g: Vec<E::G1Affine>,
}

/// 对于任何实现了 Pairing trait 的类型 E，我要为 UnivariateUniversalParams<E> 类型实现 StructuredReferenceString trait
/// 
impl<E: Pairing> StructuredReferenceString for UnivariateUniversalParams<E> {
    // 这行代码定义了一个类型别名 ProverParam，它等价于 UnivariateProverParam<E>。
    // 这意味着在这个上下文中，你可以使用 ProverParam 来代替 UnivariateProverParam<E>。
    // 这里的 E 是一个类型参数，表示 UnivariateProverParam 可以接受任何类型的 E。
    // 在 Rust 中，泛型类型需要在使用时为其类型参数提供具体的类型。例如，如果我们有一个泛型结构体 struct MyStruct<T> { ... }，我们不能直接使用 MyStruct，而需要为 T 提供一个具体的类型，如 MyStruct<i32>
    type ProverParam = UnivariateProverParam<E>;
    type VerifierParam = UnivariateVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    /// self 是 UnivariateUniversalParams<E> 类型的一个引用，因为这些方法是在为 UnivariateUniversalParams<E> 实现 StructuredReferenceString trait
    fn extract_prover_param(&self, supported_degree: usize) -> Self::ProverParam {
        /// 包含 self.powers_of_g 中从第 0 个元素到第 supported_degree 个元素的所有元素。
        /// [..=supported_degree] 是一个范围，它包含了开始和结束的索引。
        /// .to_vec() 方法将这个子向量转换为一个新的 Vec。
        let powers_of_g = self.powers_of_g[..=supported_degree].to_vec();
        /// Self::ProverParam { powers_of_g } 创建了一个新的 Self::ProverParam 类型的实例，其中 powers_of_g 是这个实例的一个字段。
        Self::ProverParam { powers_of_g }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_degree: usize) -> Self::VerifierParam {
        Self::VerifierParam {
            g: self.powers_of_g[0],
            h: self.h,
            beta_h: self.beta_h,
            powers_of_h: self.powers_of_h[..=supported_degree].to_vec(),
            powers_of_g: self.powers_of_g[..=supported_degree].to_vec(),
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for univariate polynomials to the given `supported_degree`, and
    /// returns committer key and verifier key. `supported_degree` should
    /// be in range `1..params.len()`
    /// 
    /// 这个函数在做的事情是算pk和vk：
    /// 其实就是根据prover_supported_degree和verifier_supported_degree来截取powers_of_g和powers_of_h
    /// 
    /// 返回值： Result<(Self::ProverParam, Self::VerifierParam), PCSError>：
    /// 这是一个Result类型的返回值，它有两种可能的状态。
    /// 如果函数成功执行，它将返回一个元组，其中包含两个参数：Self::ProverParam和Self::VerifierParam。
    /// 如果函数执行过程中出现错误，它将返回一个PCSError类型的错误。
    fn trim_with_verifier_degree(
        &self,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        /// 如果 prover_supported_degree 大于 self.powers_of_g 的长度，返回一个错误。
        /// 如果 verifier_supported_degree 大于 self.powers_of_h 的长度，返回一个错误。
        /// 如果 verifer_supported_degree 为 0，返回一个错误。
        
    }

}
