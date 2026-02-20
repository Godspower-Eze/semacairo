#[starknet::interface]
pub trait ISemaphoreVerifier<TContractState> {
    fn verify_groth16_proof_bn254(
        self: @TContractState, depth: u8, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}
