// Generated split verifier
use garaga::definitions::G1Point;

fn get_vk(depth: u8) -> garaga::ec::pairing::groth16::Groth16VerifyingKey::<garaga::definitions::structs::fields::u288> {
    if depth == 29 {
        return super::g16v_29_constants::vk;
    } else if depth == 30 {
        return super::g16v_30_constants::vk;
    }
    panic!("Unsupported depth")
}

fn get_ic(depth: u8) -> [G1Point; 5] {
    if depth == 29 {
        return super::g16v_29_constants::ic;
    } else if depth == 30 {
        return super::g16v_30_constants::ic;
    }
    panic!("Unsupported depth")
}

fn get_precomputed_lines(depth: u8) -> [garaga::definitions::structs::points::G2Line::<garaga::definitions::structs::fields::u288>; 176] {
    if depth == 29 {
        return super::g16v_29_constants::precomputed_lines;
    } else if depth == 30 {
        return super::g16v_30_constants::precomputed_lines;
    }
    panic!("Unsupported depth")
}

#[starknet::contract]
mod Semaphore_Groth16VerifierBN254_11 {
    use garaga::definitions::{G1G2Pair, G1Point};
    use garaga::ec_ops::{G1PointTrait, ec_safe_add};
    use garaga::groth16::{
        Groth16ProofRawTrait, multi_pairing_check_bn254_3P_2F_with_extra_miller_loop_result,
    };
    use garaga::utils::calldata::deserialize_full_proof_with_hints_bn254;
    use starknet::SyscallResultTrait;
    use super::{get_vk, get_ic, get_precomputed_lines};
    use super::super::g16v_common_constants::N_PUBLIC_INPUTS;
    use semacairo::semaphore_verifier_interface::ISemaphoreVerifier;

    const ECIP_OPS_CLASS_HASH: felt252 =
        0x312d1dd5f967eaf6f86965e3fa7acbc9d0fbd979066a17721dd913736af2f5e;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ISemaphore_Groth16VerifierBN254_11 of ISemaphoreVerifier<ContractState> {
        fn verify_groth16_proof_bn254(
            self: @ContractState, depth: u8, full_proof_with_hints: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            let fph = deserialize_full_proof_with_hints_bn254(full_proof_with_hints);
            let groth16_proof = fph.groth16_proof;
            let mpcheck_hint = fph.mpcheck_hint;
            let msm_hint = fph.msm_hint;

            groth16_proof.raw.check_proof_points(0);

            let vk = get_vk(depth);
            let ic = get_ic(depth);
            let precomputed_lines = get_precomputed_lines(depth);
            let ic_span = ic.span();

            let vk_x: G1Point = match ic_span.len() {
                0 => panic!("Malformed VK"),
                1 => *ic_span.at(0),
                _ => {
                    let mut msm_calldata: Array<felt252> = array![];
                    Serde::serialize(@ic_span.slice(1, N_PUBLIC_INPUTS), ref msm_calldata);
                    Serde::serialize(@groth16_proof.public_inputs, ref msm_calldata);
                    msm_calldata.append(0);
                    for x in msm_hint {
                        msm_calldata.append(*x);
                    }

                    let mut _vx_x_serialized = starknet::syscalls::library_call_syscall(
                        ECIP_OPS_CLASS_HASH.try_into().unwrap(),
                        selector!("msm_g1"),
                        msm_calldata.span(),
                    )
                        .unwrap_syscall();

                    ec_safe_add(
                        Serde::<G1Point>::deserialize(ref _vx_x_serialized).unwrap(), *ic_span.at(0), 0,
                    )
                },
            };
            
            let check = multi_pairing_check_bn254_3P_2F_with_extra_miller_loop_result(
                G1G2Pair { p: vk_x, q: vk.gamma_g2 },
                G1G2Pair { p: groth16_proof.raw.c, q: vk.delta_g2 },
                G1G2Pair { p: groth16_proof.raw.a.negate(0), q: groth16_proof.raw.b },
                vk.alpha_beta_miller_loop_result,
                precomputed_lines.span(),
                mpcheck_hint,
            );
            
            match check {
                Result::Ok(_) => Result::Ok(groth16_proof.public_inputs),
                Result::Err(error) => Result::Err(error),
            }
        }
    }
}
