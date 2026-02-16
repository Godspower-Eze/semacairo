#[starknet::interface]
trait ISemaphore<TContractState> {
    fn create_group(ref self: TContractState, group_id: u256, depth: u8);
    fn add_member(ref self: TContractState, group_id: u256, identity_commitment: felt252);
    fn verify_proof(
        self: @TContractState,
        group_id: u256,
        merkle_tree_root: felt252,
        signal: felt252,
        nullifier_hash: u256,
        external_nullifier: u256,
        proof: Span<felt252>,
    ) -> bool;
    fn get_root(self: @TContractState, group_id: u256) -> felt252;
    fn get_group_admin(self: @TContractState, group_id: u256) -> starknet::ContractAddress;
    fn signal(
        ref self: TContractState,
        group_id: u256,
        merkle_tree_root: felt252,
        signal: felt252,
        nullifier_hash: u256,
        external_nullifier: u256,
        proof: Span<felt252>,
    );
}

#[starknet::contract]
mod Semaphore {
    use core::array::ArrayTrait;
    use core::poseidon::poseidon_hash_span;
    use core::traits::{Into, TryInto};
    use semacairo::groth16_verifier::{
        IGroth16VerifierBN254Dispatcher, IGroth16VerifierBN254DispatcherTrait,
    };
    use semacairo::merkle_tree;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use super::ISemaphore;

    #[storage]
    struct Storage {
        group_roots: Map<u256, felt252>,
        group_depths: Map<u256, u8>,
        group_sizes: Map<u256, u256>,
        nullifiers: Map<u256, bool>, // nullifier_hash -> is_used
        // Frontier for incremental Merkle Tree
        // keys: (group_id, level) -> value
        tree_frontier: Map<(u256, u8), felt252>,
        // Zero values for each level
        zero_values: Map<u8, felt252>,
        // Address of the Groth16 verifier contract
        groth16_verifier_address: ContractAddress,
        // Admin of each group (group_id -> admin address)
        group_admins: Map<u256, ContractAddress>,
        // Track members per group: (group_id, identity_commitment) -> is_member
        group_members: Map<(u256, felt252), bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        GroupCreated: GroupCreated,
        MemberAdded: MemberAdded,
        Signal: Signal,
    }

    #[derive(Drop, starknet::Event)]
    struct GroupCreated {
        #[key]
        group_id: u256,
        depth: u8,
        admin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct MemberAdded {
        #[key]
        group_id: u256,
        index: u256,
        identity_commitment: felt252,
        root: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct Signal {
        #[key]
        group_id: u256,
        root: felt252,
        nullifier_hash: u256,
        signal: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, groth16_verifier_address: ContractAddress) {
        // Initialize zero values for a reasonable depth, e.g., 20
        let mut current_zero = 0; // Using 0 as the base zero value
        self.zero_values.write(0, current_zero);

        // Compute subsequent zero values: hash(prev, prev)
        let mut i: u8 = 1;
        while i <= 32 {
            let mut input = ArrayTrait::new();
            input.append(current_zero);
            input.append(current_zero);
            current_zero = poseidon_hash_span(input.span());
            self.zero_values.write(i, current_zero);
            i += 1;
        }

        // Store the verifier address
        self.groth16_verifier_address.write(groth16_verifier_address);
    }

    #[abi(embed_v0)]
    impl SemaphoreImpl of ISemaphore<ContractState> {
        fn create_group(ref self: ContractState, group_id: u256, depth: u8) {
            // Check if group already exists (depth != 0)
            let existing_depth = self.group_depths.read(group_id);
            assert(existing_depth == 0, 'Group already exists');
            assert(depth <= 32, 'Depth too large');

            // Set the caller as group admin
            let admin = get_caller_address();
            self.group_admins.write(group_id, admin);

            self.group_depths.write(group_id, depth);
            self.group_sizes.write(group_id, 0);

            // Initial root is the zero value at 'depth'
            let root = self.zero_values.read(depth);
            self.group_roots.write(group_id, root);

            self.emit(GroupCreated { group_id, depth, admin });
        }

        fn add_member(ref self: ContractState, group_id: u256, identity_commitment: felt252) {
            let depth = self.group_depths.read(group_id);
            assert(depth != 0, 'Group does not exist');

            // Only admin can add members
            let caller = get_caller_address();
            let admin = self.group_admins.read(group_id);
            assert(caller == admin, 'Only admin can add members');

            // Check member not already in group
            let is_member = self.group_members.read((group_id, identity_commitment));
            assert(!is_member, 'Member already in group');

            let size = self.group_sizes.read(group_id);

            // Read frontier and zero values into arrays
            let mut frontier_arr = ArrayTrait::new();
            let mut zero_vals_arr = ArrayTrait::new();
            let mut i: u8 = 0;
            while i < depth {
                frontier_arr.append(self.tree_frontier.read((group_id, i)));
                zero_vals_arr.append(self.zero_values.read(i));
                i += 1;
            }

            let (new_root, updates) = merkle_tree::insert(
                identity_commitment, depth.into(), size, frontier_arr.span(), zero_vals_arr.span(),
            );

            // Update state
            self.group_roots.write(group_id, new_root);
            self.group_sizes.write(group_id, size + 1);

            // Mark member as added
            self.group_members.write((group_id, identity_commitment), true);

            let updates_span = updates.span();
            let mut j = 0;
            while j < updates_span.len() {
                let up_box = updates_span.at(j);
                let up: merkle_tree::FrontierUpdate = *up_box;
                self.tree_frontier.write((group_id, up.level), up.node);
                j += 1;
            }

            self.emit(MemberAdded { group_id, index: size, identity_commitment, root: new_root });
        }

        fn verify_proof(
            self: @ContractState,
            group_id: u256,
            merkle_tree_root: felt252,
            signal: felt252,
            nullifier_hash: u256,
            external_nullifier: u256,
            proof: Span<felt252>,
        ) -> bool {
            // 1. Check if the root matches current root
            let current_root = self.group_roots.read(group_id);
            if current_root != merkle_tree_root {
                return false;
            }

            // 2. Call Groth16 Verifier
            let verifier_address = self.groth16_verifier_address.read();
            let dispatcher = IGroth16VerifierBN254Dispatcher { contract_address: verifier_address };

            let result = dispatcher.verify_groth16_proof_bn254(proof);

            // 3. Verify the proof result
            if result.is_err() {
                return false;
            }

            let public_inputs = result.unwrap();
            // public_inputs should be [merkle_tree_root, signal, nullifier_hash,
            // external_nullifier]
            if public_inputs.len() != 4 {
                return false;
            }
            let pi_merkle_root: u256 = *public_inputs.at(0);
            let pi_signal: u256 = *public_inputs.at(1);
            let pi_nullifier_hash: u256 = *public_inputs.at(2);
            let pi_external_nullifier: u256 = *public_inputs.at(3);

            // Compare with provided values
            // Convert felt252 to u256 for comparison
            let merkle_root_u256: u256 = merkle_tree_root.try_into().unwrap();
            let signal_u256: u256 = signal.try_into().unwrap();

            if pi_merkle_root != merkle_root_u256
                || pi_signal != signal_u256
                || pi_nullifier_hash != nullifier_hash
                || pi_external_nullifier != external_nullifier {
                return false;
            }

            true
        }

        fn get_root(self: @ContractState, group_id: u256) -> felt252 {
            self.group_roots.read(group_id)
        }

        fn get_group_admin(self: @ContractState, group_id: u256) -> ContractAddress {
            self.group_admins.read(group_id)
        }

        fn signal(
            ref self: ContractState,
            group_id: u256,
            merkle_tree_root: felt252,
            signal: felt252,
            nullifier_hash: u256,
            external_nullifier: u256,
            proof: Span<felt252>,
        ) {
            // 1. Verify correctness (Merkle root, proof structure)
            let is_valid = self
                .verify_proof(
                    group_id, merkle_tree_root, signal, nullifier_hash, external_nullifier, proof,
                );
            assert(is_valid, 'Invalid ZK Proof');

            // 2. Check and Set Nullifier
            assert(!self.nullifiers.read(nullifier_hash), 'Nullifier already used');
            self.nullifiers.write(nullifier_hash, true);

            // 3. Emit Signal
            self.emit(Signal { group_id, root: merkle_tree_root, nullifier_hash, signal });
        }
    }
    #[cfg(test)]
    mod tests {
        use snforge_std::start_cheat_caller_address_global;
        use super::SemaphoreImpl;

        fn setup() -> super::ContractState {
            let mut state = super::contract_state_for_testing();
            let dummy_verifier: starknet::ContractAddress = 0.try_into().unwrap();
            super::constructor(ref state, dummy_verifier);
            state
        }

        #[test]
        fn test_create_group_and_add_member() {
            // 1. Setup
            let mut state = setup();
            let admin: starknet::ContractAddress = 1.try_into().unwrap();
            start_cheat_caller_address_global(admin);

            // 2. Create Group
            let group_id = 1;
            let depth = 20;

            SemaphoreImpl::create_group(ref state, group_id, depth);

            // Check admin is set correctly
            let stored_admin = SemaphoreImpl::get_group_admin(@state, group_id);
            assert(stored_admin == admin, 'Admin should be caller');

            // Check root is zero value
            let root = SemaphoreImpl::get_root(@state, group_id);
            assert(root != 0, 'Root should be non-zero');

            // 3. Add Member (as admin)
            let identity_commitment = 12345;
            SemaphoreImpl::add_member(ref state, group_id, identity_commitment);

            // Check root changed
            let new_root = SemaphoreImpl::get_root(@state, group_id);
            assert(new_root != root, 'Root should change');

            // 4. Add Member 2
            let id2 = 67890;
            SemaphoreImpl::add_member(ref state, group_id, id2);

            let root2 = SemaphoreImpl::get_root(@state, group_id);
            assert(root2 != new_root, 'Root should change again');
        }

        #[test]
        #[should_panic(expected: 'Only admin can add members')]
        fn test_non_admin_cannot_add_member() {
            let mut state = setup();
            let admin: starknet::ContractAddress = 1.try_into().unwrap();
            let non_admin: starknet::ContractAddress = 2.try_into().unwrap();

            // Create group as admin
            start_cheat_caller_address_global(admin);
            SemaphoreImpl::create_group(ref state, 1, 20);

            // Try to add member as non-admin — should panic
            start_cheat_caller_address_global(non_admin);
            SemaphoreImpl::add_member(ref state, 1, 12345);
        }

        #[test]
        #[should_panic(expected: 'Member already in group')]
        fn test_duplicate_member_rejected() {
            let mut state = setup();
            let admin: starknet::ContractAddress = 1.try_into().unwrap();
            start_cheat_caller_address_global(admin);

            SemaphoreImpl::create_group(ref state, 1, 20);

            let identity_commitment = 12345;
            SemaphoreImpl::add_member(ref state, 1, identity_commitment);

            // Try to add same member again — should panic
            SemaphoreImpl::add_member(ref state, 1, identity_commitment);
        }
    }
}
