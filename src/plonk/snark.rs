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
        let (batch_proof, ..) =
            Self::batch_prove_internal::<_, _, T>(prng, circuits, prove_keys, None)?;
        Ok(batch_proof)
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
        if verify_keys.is_empty() {
            return Err(ParameterError("empty verification keys".to_string()).into());
        }
        /// 创建一个新的Verifier实例
        let verifier = Verifier::new(verify_keys[0].domain_size)?;
        /// 调用prepare_pcs_info方法来准备验证所需的信息
        let pcs_info =
            verifier.prepare_pcs_info::<T>(verify_keys, public_inputs, batch_proof, &None)?;
        /// 调用batch_verify_opening_proofs方法来验证开放证明
        if !Verifier::batch_verify_opening_proofs::<T>(
            &verify_keys[0].open_key, // all open_key are the same
            &[pcs_info],
        )? {
            return Err(PlonkError::WrongProof);
        }
        Ok(())
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
        if public_inputs.len() != proofs.len()
            || verify_keys.len() != proofs.len()
            || extra_transcript_init_msgs.len() != proofs.len()
        {
            return Err(ParameterError(format!(
                "verify_keys.len: {}, public_inputs.len: {}, proofs.len: {}, \
                 extra_transcript_msg.len: {}",
                verify_keys.len(),
                public_inputs.len(),
                proofs.len(),
                extra_transcript_init_msgs.len()
            ))
            .into());
        }
        /// 检查验证密钥是否为空
        if verify_keys.is_empty() {
            return Err(
                ParameterError("the number of instances cannot be zero".to_string()).into(),
            );
        }

        /// 对每一组初始参数生成初始化的pcs info
        let pcs_infos = parallelizable_slice_iter(verify_keys)
            .zip(parallelizable_slice_iter(proofs))
            .zip(parallelizable_slice_iter(public_inputs))
            .zip(parallelizable_slice_iter(extra_transcript_init_msgs))
            .map(|(((&vk, &proof), &pub_input), extra_msg)| {
                let verifier = Verifier::new(vk.domain_size)?;
                verifier.prepare_pcs_info::<T>(
                    &[vk],
                    &[pub_input],
                    &(*proof).clone().into(),
                    extra_msg,
                )
            })
            .collect::<Result<Vec<_>, PlonkError>>()?;

        /// 调用batch_verify_opening_proofs方法来验证开放证明
        if !Verifier::batch_verify_opening_proofs::<T>(
            &verify_keys[0].open_key, // all open_key are the same
            &pcs_infos,
        )? {
            return Err(PlonkError::WrongProof);
        }
        Ok(())
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
        if circuits.is_empty() {
            return Err(ParameterError("zero number of circuits/proving keys".to_string()).into());
        }
        /// 这段Rust代码在检查circuits（电路）的数量是否等于prove_keys（证明密钥）的数量。
        /// 为啥要这么做，没懂。。
        if circuits.len() != prove_keys.len() {
            return Err(ParameterError(format!(
                "the number of circuits {} != the number of proving keys {}",
                circuits.len(),
                prove_keys.len()
            ))
            .into());
        }

        /// 这段Rust代码是在对每个电路（circuit）和对应的证明密钥（proving key）进行一系列的验证。
        /// 这些验证确保了电路和证明密钥的一些关键属性是匹配的：
        ///    检查每个电路的评估域大小是否都等于n
        ///    检查证明密钥的域大小是否等于n
        ///    检查电路的inputs数量是否等于证明密钥的inputs数量
        ///    检查电路是否支持查找是否等于证明密钥是否有plookup公钥
        ///    检查电路的线路类型数量是否等于num_wire_types
        /// 这行代码获取第一个电路的评估域大小，并将其存储在变量n中
        /// 这些关键检查其实我不太理解为啥要这么做，以及为啥要做这么多。。
        let n = circuits[0].eval_domain_size()?;
        /// 这行代码获取第一个电路的线路类型数量，并将其存储在变量num_wire_types中
        let num_wire_types = circuits[0].num_wire_types();
        for (circuit, pk) in circuits.iter().zip(prove_keys.iter()) {
            /// 检查每个电路的评估域大小是否都等于n
            if circuit.eval_domain_size()? != n {
                return Err(ParameterError(format!(
                    "circuit domain size {} != expected domain size {}",
                    circuit.eval_domain_size()?,
                    n
                ))
                .into());
            }
            /// 检查证明密钥的域大小是否等于n
            if pk.domain_size() != n {
                return Err(ParameterError(format!(
                    "proving key domain size {} != expected domain size {}",
                    pk.domain_size(),
                    n
                ))
                .into());
            }
            /// 检查电路的inputs数量是否等于证明密钥的inputs数量
            if circuit.num_inputs() != pk.vk.num_inputs {
                return Err(ParameterError(format!(
                    "circuit.num_inputs {} != prove_key.num_inputs {}",
                    circuit.num_inputs(),
                    pk.vk.num_inputs
                ))
                .into());
            }
            // 这行代码检查电路是否支持查找是否等于证明密钥是否有plookup公钥
            if circuit.support_lookup() != pk.plookup_pk.is_some() {
                return Err(ParameterError(
                    "Mismatched Plonk types between the proving key and the circuit".to_string(),
                )
                .into());
            }
            /// 这行代码检查电路的线路类型数量是否等于num_wire_types
            if circuit.num_wire_types() != num_wire_types {
                return Err(ParameterError("inconsistent plonk circuit types".to_string()).into());
            }
        }

        // Initialize transcript
        /// 这段代码是在进行一些初始化和验证操作
        /// 首先创建一个新的PlonkTranscript实例
        let mut transcript = T::new(b"PlonkProof");
        /// 如果extra_transcript_init_msg不为空，就将其附加到transcript上
        if let Some(msg) = extra_transcript_init_msg {
            transcript.append_message(EXTRA_TRANSCRIPT_MSG_LABEL, &msg)?;
        }
        /// 这行代码是在将验证密钥和公共输入附加到transcript上
        for (pk, circuit) in prove_keys.iter().zip(circuits.iter()) {
            transcript.append_vk_and_pub_input(&pk.vk, &circuit.public_input()?)?;
        }
        // Initialize verifier challenges and online polynomial oracles.
        let mut challenges = Challenges::default();
        let mut online_oracles = vec![Oracles::default(); circuits.len()];
        let prover = Prover::new(n, num_wire_types)?;

        // Round 1
        /// 这一轮次本质上是在对电路做一系列的运算，他把电路转换成了线路多项式和公开输入多项式，并且计算了线路多项式承诺。
        /// 这些计算是直接调用prover的run_1st_round方法完成的。
        /// 最终将结果存储在online_oracles和wires_poly_comms_vec中。
        /// 这行代码创建了一个新的向量wires_poly_comms_vec，用于存储每个电路的线路多项式承诺
        let mut wires_poly_comms_vec = vec![];
        ///遍历每个电路
        for i in 0..circuits.len() {
            /// 这行代码运行prover的第一轮方法
            /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥和电路。
            /// 方法的返回值是一个元组，包含线路多项式承诺、线路多项式和公开输入多项式。
            let ((wires_poly_comms, wire_polys), pi_poly) =
                prover.run_1st_round(prng, &prove_keys[i].commit_key, circuits[i])?;
            /// 将线路多项式存储在对应的在线预言机中。
            online_oracles[i].wire_polys = wire_polys;
            /// 将公开输入多项式存储在对应的在线预言机中。
            online_oracles[i].pub_inp_poly = pi_poly;
            /// 将线路多项式承诺添加到transcript中
            transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
            /// 将线路多项式承诺添加到wires_poly_comms_vec中
            wires_poly_comms_vec.push(wires_poly_comms);
        }

        // Round 2
        /// 这里主要做的是线约束的多项式和对应的commitment的生成
        /// 这些计算是直接调用的prover的run_2nd_round方法完成的。
        challenges.beta = transcript.get_and_append_challenge::<E>(b"beta")?;
        challenges.gamma = transcript.get_and_append_challenge::<E>(b"gamma")?;
        /// 用于存储每个电路的乘积置换多项式承诺（product permutation polynomial commitments）
        let mut prod_perm_poly_comms_vec = vec![];
        /// 这行代码运行prover的第二轮方法
        /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥、电路和挑战。
        /// 方法的返回值是一个元组，包含乘积置换多项式承诺和乘积置换多项式
        for i in 0..circuits.len() {
            let (prod_perm_poly_comm, prod_perm_poly) =
                prover.run_2nd_round(prng, &prove_keys[i].commit_key, circuits[i], &challenges)?;
            online_oracles[i].prod_perm_poly = prod_perm_poly;
            transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
            prod_perm_poly_comms_vec.push(prod_perm_poly_comm);
        }

        // Round 3
        /// 这里主要是计算quotient polynomial的commitment
        /// 这些计算是直接调用的prover的run_3rd_round方法完成的。
        /// 这行代码从记录中获取并添加一个名为"alpha"的挑战，并将其存储在challenges.alpha中
        challenges.alpha = transcript.get_and_append_challenge::<E>(b"alpha")?;
        /// 这行代码运行prover的第三轮方法
        /// 输入参数是伪随机数生成器（prng）、证明密钥的承诺密钥、证明密钥、挑战、在线预言机和线路类型数量。
        /// 方法的返回值是一个元组，包含商多项式承诺和商多项式
        let (split_quot_poly_comms, split_quot_polys) = prover.run_3rd_round(
            prng,
            &prove_keys[0].commit_key,
            prove_keys,
            &challenges,
            &online_oracles,
            num_wire_types,
        )?;
        /// 将商多项式承诺添加到transcript中
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;

        // Round 4
        /// 这里主要是计算多项式评估
        /// 这些计算是直接调用的prover的compute_evaluations方法完成的。
        /// 这行代码从记录中获取并添加一个名为"zeta"的挑战，并将其存储在challenges.zeta中
        challenges.zeta = transcript.get_and_append_challenge::<E>(b"zeta")?;
        /// 这行代码创建了一个新的向量poly_evals_vec，用于存储每个电路的多项式评估（polynomial evaluations）
        let mut poly_evals_vec = vec![];
        for i in 0..circuits.len() {
            /// 这行代码运行prover的compute_evaluations方法，
            /// 输入参数是证明密钥、挑战、在线预言机和线类型的数量。
            /// 方法的返回值是多项式评估
            let poly_evals = prover.compute_evaluations(
                prove_keys[i],
                &challenges,
                &online_oracles[i],
                num_wire_types,
            );
            transcript.append_proof_evaluations::<E>(&poly_evals)?;
            poly_evals_vec.push(poly_evals);
        }


        // Round 5
        /// 这一步主要在算多项式评估的证明，就是pi
        /// 这行代码从记录中获取并添加一个名为"v"的挑战，并将其存储在challenges.v中
        challenges.v = transcript.get_and_append_challenge::<E>(b"v")?;
        /// 这行代码运行prover的compute_opening_proofs方法
        /// 输入参数是证明密钥的承诺密钥、证明密钥、挑战zeta、挑战v、在线预言机和线性多项式。
        /// 方法的返回值是一个元组，包含开放证明和偏移开放证明
        let (opening_proof, shifted_opening_proof) = prover.compute_opening_proofs(
            &prove_keys[0].commit_key,
            prove_keys,
            &challenges.zeta,
            &challenges.v,
            &online_oracles,
            &lin_poly,
        )?;

        Ok((
            BatchProof {
                wires_poly_comms_vec,
                prod_perm_poly_comms_vec,
                poly_evals_vec,
                // //理论上来说，不用plonkup应该删掉这部分
                // plookup_proofs_vec,
                split_quot_poly_comms,
                opening_proof,
                shifted_opening_proof,
            },
            online_oracles,
            challenges,
        ))
    }
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
        use ark_ec::{scalar_mul::fixed_base::FixedBase, CurveGroup};
        use ark_ff::PrimeField;
        use ark_std::{end_timer, start_timer, UniformRand};

        let setup_time = start_timer!(|| format!("KZG10::Setup with degree {}", max_degree));
        // 这个随机数其实就是tau
        let beta = E::ScalarField::rand(rng);
        // 这行代码生成一个随机的G1群元素g1
        let g = E::G1::rand(rng);
        // 这行代码生成一个随机的G2群元素g2
        let h = E::G2::rand(rng);

        let mut powers_of_beta = vec![E::ScalarField::one()];

        // 这里在计算tau^1, tau^2, tau^3, ..., tau^max_degree
        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBase::get_mul_window_size(max_degree + 1);

        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
        let g_time = start_timer!(|| "Generating powers of G");
        // TODO: parallelization
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
        // 这里用MSM来计算pk：g^tau^1, g^tau^2, g^tau^3, ..., g^tau^max_degree
        let powers_of_g =
            FixedBase::msm::<E::G1>(scalar_bits, window_size, &g_table, &powers_of_beta);
        end_timer!(g_time);

        let powers_of_g = E::G1::normalize_batch(&powers_of_g);

        let h = h.into_affine();
        let beta_h = (h * beta).into_affine();

        let pp = UniversalSrs {
            powers_of_g,
            h,
            beta_h,
            powers_of_h: vec![h, beta_h],
        };
        end_timer!(setup_time);
        Ok(pp)
    }

    /// 1. Input a circuit and the SRS, precompute the proving key and verification key.
    /// 本质上就是在准备pk和vk
    /// 但是不是很明白为什么需要有一段计算selector和extended permutation的poly的commitment
    fn preprocess<C: Arithmetization<E::ScalarField>>(
        srs: &Self::UniversalSRS,
        circuit: &C,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        // Make sure the SRS can support the circuit (with hiding degree of 2 for zk)
        let domain_size = circuit.eval_domain_size()?;
        let srs_size = circuit.srs_size()?;
        let num_inputs = circuit.num_inputs();
        if srs.max_degree() < circuit.srs_size()? {
            return Err(PlonkError::IndexTooLarge);
        }
        // 1. Compute selector and permutation polynomials.
        // 调用circuit里面的方法，计算selector poly和extended permutation poly
        let selectors_polys = circuit.compute_selector_polynomials()?;
        let sigma_polys = circuit.compute_extended_permutation_polynomials()?;

        // Compute Plookup proving key if support lookup.
        // 准备Plookup所需要的参数
        let plookup_pk = if circuit.support_lookup() {
            let range_table_poly = circuit.compute_range_table_polynomial()?;
            let key_table_poly = circuit.compute_key_table_polynomial()?;
            let table_dom_sep_poly = circuit.compute_table_dom_sep_polynomial()?;
            let q_dom_sep_poly = circuit.compute_q_dom_sep_polynomial()?;
            Some(PlookupProvingKey {
                range_table_poly,
                key_table_poly,
                table_dom_sep_poly,
                q_dom_sep_poly,
            })
        } else {
            None
        };

        // 2. Compute VerifyingKey
        // 用kzg的方法计算选择器和排列多项式的commitment
        // 这行代码从SRS中裁剪出一个新的SRS，其大小等于电路所需的SRS大小。裁剪后的SRS包含一个提交密钥（commit key）和一个打开密钥（open key）
        let (commit_key, open_key) = srs.trim(srs_size)?;
        // 这段代码首先通过parallelizable_slice_iter函数创建一个对选择器多项式的迭代器
        // 然后对每个多项式使用UnivariateKzgPCS::commit函数计算其承诺。
        // 所有的承诺被收集到一个向量中，形成selector_comms。
        let selector_comms = parallelizable_slice_iter(&selectors_polys)
            .map(|poly| UnivariateKzgPCS::commit(&commit_key, poly).map_err(PlonkError::PCSError))
            .collect::<Result<Vec<_>, PlonkError>>()?
            .into_iter()
            .collect();
        // 和上面类似，但是这里是计算排列多项式的承诺
        let sigma_comms = parallelizable_slice_iter(&sigma_polys)
            .map(|poly| UnivariateKzgPCS::commit(&commit_key, poly).map_err(PlonkError::PCSError))
            .collect::<Result<Vec<_>, PlonkError>>()?
            .into_iter()
            .collect();

        // Compute Plookup verifying key if support lookup.
        let plookup_vk = match circuit.support_lookup() {
            false => None,
            true => Some(PlookupVerifyingKey {
                range_table_comm: UnivariateKzgPCS::commit(
                    &commit_key,
                    &plookup_pk.as_ref().unwrap().range_table_poly,
                )?,
                key_table_comm: UnivariateKzgPCS::commit(
                    &commit_key,
                    &plookup_pk.as_ref().unwrap().key_table_poly,
                )?,
                table_dom_sep_comm: UnivariateKzgPCS::commit(
                    &commit_key,
                    &plookup_pk.as_ref().unwrap().table_dom_sep_poly,
                )?,
                q_dom_sep_comm: UnivariateKzgPCS::commit(
                    &commit_key,
                    &plookup_pk.as_ref().unwrap().q_dom_sep_poly,
                )?,
            }),
        };

        let vk = VerifyingKey {
            domain_size,
            num_inputs,
            selector_comms,
            sigma_comms,
            k: compute_coset_representatives(circuit.num_wire_types(), Some(domain_size)),
            open_key,
            plookup_vk,
            is_merged: false,
        };

        // Compute ProvingKey (which includes the VerifyingKey)
        let pk = ProvingKey {
            sigmas: sigma_polys,
            selectors: selectors_polys,
            commit_key,
            vk: vk.clone(),
            plookup_pk,
        };

        Ok((pk, vk))
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
        let (batch_proof, ..) = Self::batch_prove_internal::<_, _, T>(
            rng,
            &[circuit],
            &[prove_key],
            extra_transcript_init_msg,
        )?;
        // 这行代码创建了一个新的Proof实例，其中包含了批量证明中的各种信息
        // 如线性多项式的承诺、排列多项式的乘积的承诺、分割商多项式的承诺、开放证明、偏移开放证明、多项式评估和Plookup证明
        Ok(Proof {
            wires_poly_comms: batch_proof.wires_poly_comms_vec[0].clone(),
            prod_perm_poly_comm: batch_proof.prod_perm_poly_comms_vec[0],
            split_quot_poly_comms: batch_proof.split_quot_poly_comms,
            opening_proof: batch_proof.opening_proof,
            shifted_opening_proof: batch_proof.shifted_opening_proof,
            poly_evals: batch_proof.poly_evals_vec[0].clone(),
            plookup_proof: batch_proof.plookup_proofs_vec[0].clone(),
        })
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
        Self::batch_verify::<T>(
            &[verify_key],
            &[public_input],
            &[proof],
            &[extra_transcript_init_msg],
        )
    }
}

