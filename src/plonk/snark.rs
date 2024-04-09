use super::{
    prover::Prover,
    structs::{
        BatchProof, Challenges, Oracles, PlookupProof, PlookupProvingKey, PlookupVerifyingKey,
        Proof, ProvingKey, VerifyingKey,
    },
    verifier::Verifier,
    UniversalSNARK,
};
use crate::{
    constants::EXTRA_TRANSCRIPT_MSG_LABEL,
    errors::{PlonkError, SnarkError::ParameterError},
    proof_system::structs::UniversalSrs,
    transcript::*,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_ff::{Field, One};
use ark_std::{
    format,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_primitives::{
    pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme, StructuredReferenceString},
    rescue::RescueParameter,
};
use jf_relation::{
    constants::compute_coset_representatives, gadgets::ecc::SWToTEConParam, Arithmetization,
};
use jf_utils::par_utils::parallelizable_slice_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A Plonk instantiated with KZG PCS
/// PCS: Polynomial Commitment Scheme
pub struct PlonkKzgSnark<E: Pairing>(PhantomData<E>);

// 这里实现的是plonk的主流程，包括
/// 1. 初始化
/// 2. 对电路做一系列的运算，他把电路转换成了线路多项式和公开输入多项式，并且计算了线路多项式承诺。
/// 3. 计算线约束的多项式和对应的commitment的生成
/// 4. 计算多项式评估
/// 5. 计算多项式评估的证明，就是pi
/// 中间还穿插了对plonkup的支持
/// 细节实现主要还是基于prover当中实现的方法
impl<E, F, P> PlonkKzgSnark<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    ///RescueParameter可能与Rescue哈希函数有关
    /// SWToTEConParam可能与Short Weierstrass到Twisted Edwards曲线的转换有关
    /// Short Weierstrass形式的椭圆曲线的方程通常写作y^2 = x^3 + ax + b。
    /// Twisted Edwards形式的椭圆曲线的方程通常写作ax^2 + y^2 = 1 + dx^2y^2。
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    #[allow(clippy::new_without_default)]
    /// A new Plonk KZG SNARK
    pub fn new() -> Self {
        Self(PhantomData)
    }

    /// Generate an aggregated Plonk proof for multiple instances.
    /// 这个函数本质上是在调用batch_prove_internal方法，然后将结果的第一个元素赋值给batch_proof
    pub fn batch_prove<C, R, T>(
        prng: &mut R,
        circuits: &[&C],
        prove_keys: &[&ProvingKey<E>],
    ) -> Result<BatchProof<E>, PlonkError>
    where
        C: Arithmetization<E::ScalarField>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        /// 调用batch_prove_internal方法来生成证明，然后将结果的第一个元素赋值给batch_proof
        /// let (batch_proof, ..) =：这是一个模式匹配，它将batch_prove_internal方法返回的元组的第一个元素赋值给batch_proof，并忽略其他元素。
        /// ::<_, _, T>是类型参数的部分，其中_表示让编译器推断类型，T是明确指定的类型。
        
    }

    /// Verify a single aggregated Plonk proof.
    /// 这个函数的功能是验证一个聚合的Plonk证明。
    /// 它首先检查验证密钥是否为空，然后创建一个Verifier实例
    /// 准备PCS信息（调用prepare_pcs_info），验证开启证明(调用batch_verify_opening_proofs)，最后返回验证的结果。
    pub fn verify_batch_proof<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::ScalarField]],
        batch_proof: &BatchProof<E>,
    ) -> Result<(), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        
        /// 创建一个新的Verifier实例
        
        /// 调用prepare_pcs_info方法来准备验证所需的信息

        /// 调用batch_verify_opening_proofs方法来验证开放证明

    }

    /// Batch verify multiple SNARK proofs (w.r.t. different verifying keys).
    /// 这个方法主要用于批量验证多个独立的证明。
    /// 原理就是对每一组初始参数生成初始化的pcs info，然后调用batch_verify_opening_proofs方法来验证开放证明。
    /// 和上一个的区别：verify_batch_proof用于验证一个聚合的证明，而batch_verify用于批量验证多个独立的证明。
    pub fn batch_verify<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::ScalarField]],
        proofs: &[&Proof<E>],
        extra_transcript_init_msgs: &[Option<Vec<u8>>],
    ) -> Result<(), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        /// 检查所有输入的切片长度是否相等
       
        /// 检查验证密钥是否为空

        /// 对每一组初始参数生成初始化的pcs info
       
        /// 调用batch_verify_opening_proofs方法来验证开放证明
       
    }

    /// An internal private API for ease of testing
    ///
    /// Batchly compute a Plonk proof for multiple instances. Return the batch
    /// proof and the corresponding online polynomial oracles and
    /// challenges. Refer to Sec 8.4 of https://eprint.iacr.org/2019/953.pdf
    ///
    /// `circuit` and `prove_key` has to be consistent (with the same evaluation
    /// domain etc.), otherwise return error.
    #[allow(clippy::type_complexity)]
    fn batch_prove_internal<C, R, T>(
        /// a mutable reference to a pseudorandom number generator.
        prng: &mut R,
        circuits: &[&C],
        prove_keys: &[&ProvingKey<E>],
        extra_transcript_init_msg: Option<Vec<u8>>,
    ) -> Result<
        (
            BatchProof<E>,
            Vec<Oracles<E::ScalarField>>,
            Challenges<E::ScalarField>,
        ),
        PlonkError,
    >
    where
        C: Arithmetization<E::ScalarField>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
       
        /// 这段Rust代码在检查circuits（电路）的数量是否等于prove_keys（证明密钥）的数量。

        /// 这段Rust代码是在对每个电路（circuit）和对应的证明密钥（proving key）进行一系列的验证。
        /// 这些验证确保了电路和证明密钥的一些关键属性是匹配的：
        ///    检查每个电路的评估域大小是否都等于n
        ///    检查证明密钥的域大小是否等于n
        ///    检查电路的inputs数量是否等于证明密钥的inputs数量
        ///    检查电路是否支持查找是否等于证明密钥是否有plookup公钥
        ///    检查电路的线路类型数量是否等于num_wire_types
        /// 这行代码获取第一个电路的评估域大小，并将其存储在变量n中

        // Initialize transcript
        /// 这段代码是在进行一些初始化和验证操作
        /// 首先创建一个新的PlonkTranscript实例

        /// 如果extra_transcript_init_msg不为空，就将其附加到transcript上
       
        /// 这行代码是在将验证密钥和公共输入附加到transcript上
        
        // Initialize verifier challenges and online polynomial oracles.
        
        // Round 1
        /// 这一轮次本质上是在对电路做一系列的运算，他把电路转换成了线路多项式和公开输入多项式，并且计算了线路多项式承诺。
        /// 这些计算是直接调用prover的run_1st_round方法完成的。
        /// 最终将结果存储在online_oracles和wires_poly_comms_vec中。
        /// 这行代码创建了一个新的向量wires_poly_comms_vec，用于存储每个电路的线路多项式承诺

        ///遍历每个电路
        
            /// 这行代码运行prover的第一轮方法
            /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥和电路。
            /// 方法的返回值是一个元组，包含线路多项式承诺、线路多项式和公开输入多项式。
            
            /// 将线路多项式存储在对应的在线预言机中。
            
            /// 将公开输入多项式存储在对应的在线预言机中。
            
            /// 将线路多项式承诺添加到transcript中
            
            /// 将线路多项式承诺添加到wires_poly_comms_vec中
            
        }

        // Round 2
        /// 这里主要做的是线约束的多项式和对应的commitment的生成
        /// 这些计算是直接调用的prover的run_2nd_round方法完成的。
        
        /// 用于存储每个电路的乘积置换多项式承诺（product permutation polynomial commitments）
        
        /// 这行代码运行prover的第二轮方法
        /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥、电路和挑战。
        /// 方法的返回值是一个元组，包含乘积置换多项式承诺和乘积置换多项式
        

        // Round 3
        /// 这里主要是计算quotient polynomial的commitment
        /// 这些计算是直接调用的prover的run_3rd_round方法完成的。
        /// 这行代码从记录中获取并添加一个名为"alpha"的挑战，并将其存储在challenges.alpha中
        
        /// 这行代码运行prover的第三轮方法
        /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥、证明密钥、挑战、在线预言机和线路类型数量。
        /// 方法的返回值是一个元组，包含商多项式承诺和商多项式
        
        /// 将商多项式承诺添加到transcript中
        
        // Round 4
        /// 这里主要是计算多项式评估
        /// 这些计算是直接调用的prover的compute_evaluations方法完成的。
        /// 这行代码从记录中获取并添加一个名为"zeta"的挑战，并将其存储在challenges.zeta中
       
        /// 这行代码创建了一个新的向量poly_evals_vec，用于存储每个电路的多项式评估（polynomial evaluations）
       


        // Round 5
        /// 这一步主要在算多项式评估的证明，就是pi
        /// 这行代码从记录中获取并添加一个名为"v"的挑战，并将其存储在challenges.v中
       
        /// 这行代码运行prover的compute_opening_proofs方法
        /// 输入参数是证明密钥的承诺密钥、证明密钥、挑战zeta、挑战v、在线预言机和线性多项式。
        /// 方法的返回值是一个元组，包含开放证明和偏移开放证明
       

       
    
}

// 这里实现的是通用的SNARK接口
/// 主要调用了PlonkKzgSnark的方法
/// 步骤是：
///     1. 生成通用的结构引用字符串（SRS），本质上是在准备KZG的所有的参数
///     2. 准备pk和vk
///     3. 生成证明，本质上就是用batch_prove_internal方法来生成证明
///     4. 验证证明，本质上就是用batch_verify方法来验证开放证明

impl<E, F, P> UniversalSNARK<E> for PlonkKzgSnark<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    type Proof = Proof<E>;
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type UniversalSRS = UniversalSrs<E>;
    type Error = PlonkError;

    #[cfg(any(test, feature = "test-srs"))]
    
    /// 该函数用于生成通用的结构引用字符串（SRS）
    /// 本质上是在准备KZG的所有的参数
    fn universal_setup_for_testing<R: RngCore + CryptoRng>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<Self::UniversalSRS, Self::Error> {
        

        // 这里在计算tau^1, tau^2, tau^3, ..., tau^max_degree
       
        // 这里用MSM来计算pk：g^tau^1, g^tau^2, g^tau^3, ..., g^tau^max_degree
    
    }

    /// 1. Input a circuit and the SRS, precompute the proving key and verification key.
    /// 本质上就是在准备pk和vk
    /// 但是不是很明白为什么需要有一段计算selector和extended permutation的poly的commitment
    fn preprocess<C: Arithmetization<E::ScalarField>>(
        srs: &Self::UniversalSRS,
        circuit: &C,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        // Make sure the SRS can support the circuit (with hiding degree of 2 for zk)
       
        // 1. Compute selector and permutation polynomials.
        // 调用circuit里面的方法，计算selector poly和extended permutation poly
       
        // Compute Plookup proving key if support lookup.
        // 准备Plookup所需要的参数

        // 2. Compute VerifyingKey
        // 用kzg的方法计算选择器和排列多项式的commitment
        // 这行代码从SRS中裁剪出一个新的SRS，其大小等于电路所需的SRS大小。裁剪后的SRS包含一个提交密钥（commit key）和一个打开密钥（open key）
       
        // 这段代码首先通过parallelizable_slice_iter函数创建一个对选择器多项式的迭代器
        // 然后对每个多项式使用UnivariateKzgPCS::commit函数计算其承诺。
        // 所有的承诺被收集到一个向量中，形成selector_comms。
       
        // 和上面类似，但是这里是计算排列多项式的承诺

        // Compute ProvingKey (which includes the VerifyingKey)
       
    }

    /// Compute a Plonk proof.
    /// Refer to Sec 8.4 of <https://eprint.iacr.org/2019/953.pdf>
    ///
    /// `circuit` and `prove_key` has to be consistent (with the same evaluation
    /// domain etc.), otherwise return error.
    /// 这里本质上就是用batch_prove_internal来生成批量的证明
    /// 然后将结果转换成一个自己的定义的Proof实例
    fn prove<C, R, T>(
        rng: &mut R,
        circuit: &C,
        prove_key: &Self::ProvingKey,
        extra_transcript_init_msg: Option<Vec<u8>>,
    ) -> Result<Self::Proof, Self::Error>
    where
        C: Arithmetization<E::ScalarField>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        // 这行代码调用了batch_prove_internal函数来生成一个批量证明。这个证明包含了所有电路的证明。
       
        // 这行代码创建了一个新的Proof实例，其中包含了批量证明中的各种信息
        // 如线性多项式的承诺、排列多项式的乘积的承诺、分割商多项式的承诺、开放证明、偏移开放证明、多项式评估和Plookup证明
        
    }

    fn verify<T>(
        verify_key: &Self::VerifyingKey,
        public_input: &[E::ScalarField],
        proof: &Self::Proof,
        extra_transcript_init_msg: Option<Vec<u8>>,
    ) -> Result<(), Self::Error>
    where
        T: PlonkTranscript<F>,
    {
       
    }
}

