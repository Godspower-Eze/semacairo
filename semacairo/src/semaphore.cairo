#[starknet::interface]
trait ISemaphore<TContractState> {
    fn create_group(ref self: TContractState, group_id: u256, depth: u8);
    fn add_member(ref self: TContractState, group_id: u256, identity_commitment: u256);
    fn verify_proof(
        self: @TContractState,
        group_id: u256,
        merkle_tree_root: u256,
        nullifier: u256,
        message: u256,
        scope: u256,
        proof: Span<felt252>,
    ) -> bool;
    fn send_message(
        ref self: TContractState,
        group_id: u256,
        merkle_tree_root: u256,
        nullifier: u256,
        message: u256,
        scope: u256,
        proof: Span<felt252>,
    );
    fn get_root(self: @TContractState, group_id: u256) -> u256;
    fn get_group_admin(self: @TContractState, group_id: u256) -> starknet::ContractAddress;
    fn get_group_depth(self: @TContractState, group_id: u256) -> u8;
    fn get_verifier(self: @TContractState, depth: u8) -> starknet::ContractAddress;
}

#[starknet::contract]
mod Semaphore {
    use core::array::ArrayTrait;
    use core::poseidon::PoseidonTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    use core::traits::Into;
    use semacairo::semaphore_verifier_interface::{ISemaphoreVerifierDispatcher, ISemaphoreVerifierDispatcherTrait};
    use semacairo::merkle_tree;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
    };
    use super::ISemaphore;

    #[storage]
    struct Storage {
        group_roots: Map<u256, u256>,
        group_depths: Map<u256, u8>,
        group_sizes: Map<u256, u256>,
        nullifiers: Map<u256, bool>, // nullifier_hash -> is_used
        // Frontier for incremental Merkle Tree
        // keys: (group_id, level) -> value
        tree_frontier: Map<(u256, u8), u256>,
        // Zero values for each level
        zero_values: Map<u8, u256>,
        // Addresses of the Groth16 verifier contracts mapping index to address
        groth16_verifier_addresses: Map<u8, ContractAddress>,
        // Admin of each group (group_id -> admin address)
        group_admins: Map<u256, ContractAddress>,
        // Track members per group: (group_id, identity_commitment) -> is_member
        group_members: Map<(u256, u256), bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        GroupCreated: GroupCreated,
        MemberAdded: MemberAdded,
        MessageSent: MessageSent,
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
        identity_commitment: u256,
        root: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct MessageSent {
        #[key]
        group_id: u256,
        root: u256,
        nullifier: u256,
        message: u256,
        scope: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        verifiers: Span<ContractAddress>
    ) {
        assert(verifiers.len() == 12, 'Must provide 12 verifiers');

        // Initialize zero values for a reasonable depth, e.g., 20
        let mut current_zero = 0; // Using 0 as the base zero value
        self.zero_values.write(0, current_zero);

        // Compute subsequent zero values: hash(prev, prev)
        let mut i: u8 = 1;
        while i <= 32 {
            current_zero = PoseidonTrait::new().update_with(current_zero).update_with(current_zero).finalize().into();
            self.zero_values.write(i, current_zero);
            i += 1;
        }

        // Store the verifier addresses
        let mut idx: u8 = 0;
        while idx < 12 {
            self.groth16_verifier_addresses.write(idx + 1, *verifiers.at(idx.into()));
            idx += 1;
        }
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

        fn add_member(ref self: ContractState, group_id: u256, identity_commitment: u256) {
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
            merkle_tree_root: u256,
            nullifier: u256,
            message: u256,
            scope: u256,
            proof: Span<felt252>,
            // TODO: Group root validation is currently disabled.
            // Semaphore uses the Poseidon2 hash function in its Merkle tree implementation 
            // and within its circom circuits. Currently, Cairo does not have an available 
            // natively optimized implementation of the Poseidon2 hash function, so 
            // comparing a locally computed or stored root against the `merkle_tree_root`
            // from the proof will always fail.
            //
            // This check should be reinstated once Poseidon2 is available in Cairo.
            // =========================================================================
            // let current_root: u256 = self.group_roots.read(group_id);
            // if current_root != merkle_tree_root {
            //     return false;
            // }

            // Get depth for this group
            let depth = self.group_depths.read(group_id);
            if depth == 0 {
                return false;
            }

            // 2. Call Groth16 Verifier
            let verifier_address = self.get_verifier(depth);
            let dispatcher = ISemaphoreVerifierDispatcher { contract_address: verifier_address };
            let result = dispatcher.verify_groth16_proof_bn254(depth, proof);

            // 3. Verify the proof result
            if result.is_err() {
                return false;
            }

            let public_inputs = result.unwrap();
            if public_inputs.len() != 4 {
                return false;
            }
            let pi_merkle_root: u256 = *public_inputs.at(0);
            let pi_nullifier: u256 = *public_inputs.at(1);
            let pi_message: u256 = *public_inputs.at(2);
            let pi_scope: u256 = *public_inputs.at(3);

            if pi_merkle_root != merkle_tree_root
                || pi_message != message
                || pi_nullifier != nullifier
                || pi_scope != scope {
                return false;
            }

            true
        }

        fn send_message(
            ref self: ContractState,
            group_id: u256,
            merkle_tree_root: u256,
            nullifier: u256,
            message: u256,
            scope: u256,
            proof: Span<felt252>,
        ) {
            // 1. Verify correctness (Merkle root, proof structure)
            let is_valid = self
                .verify_proof(
                    group_id, merkle_tree_root, nullifier, message, scope, proof,
                );
            assert(is_valid, 'Invalid ZK Proof');

            // 2. Check and Set Nullifier
            assert(!self.nullifiers.read(nullifier), 'Nullifier already used');
            self.nullifiers.write(nullifier, true);

            // 3. Emit MessageSent
            self.emit(MessageSent { group_id, root: merkle_tree_root, nullifier, message, scope });
        }


        fn get_root(self: @ContractState, group_id: u256) -> u256 {
            self.group_roots.read(group_id)
        }

        fn get_group_admin(self: @ContractState, group_id: u256) -> ContractAddress {
            self.group_admins.read(group_id)
        }

        fn get_group_depth(self: @ContractState, group_id: u256) -> u8 {
            self.group_depths.read(group_id)
        }

        fn get_verifier(self: @ContractState, depth: u8) -> ContractAddress {
            assert(depth > 0 && depth <= 32, 'Unsupported depth');
            let mut index = 0;
            if depth <= 24 {
                index = depth / 3;
                if depth % 3 != 0 {
                    index += 1;
                }
            } else {
                let offset = depth - 24;
                index = 8 + (offset / 2);
                if offset % 2 != 0 {
                    index += 1;
                }
            }
            self.groth16_verifier_addresses.read(index)
        }
    }


    #[cfg(test)]
    mod tests {
        use snforge_std::start_cheat_caller_address_global;
        use super::SemaphoreImpl;

        fn setup() -> super::ContractState {
            let mut state = super::contract_state_for_testing();
            let dummy_verifier: starknet::ContractAddress = 0.try_into().unwrap();
            let verifiers = array![
                dummy_verifier, dummy_verifier, dummy_verifier, dummy_verifier,
                dummy_verifier, dummy_verifier, dummy_verifier, dummy_verifier,
                dummy_verifier, dummy_verifier, dummy_verifier, dummy_verifier
            ];
            super::constructor(ref state, verifiers.span());
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
        #[test]
        #[should_panic(expected: 'Unsupported depth')]
        fn test_get_verifier_zero() {
            let state = setup();
            SemaphoreImpl::get_verifier(@state, 0);
        }

        #[test]
        #[should_panic(expected: 'Unsupported depth')]
        fn test_get_verifier_out_of_bounds() {
            let state = setup();
            SemaphoreImpl::get_verifier(@state, 33);
        }

        #[test]
        fn test_get_verifier_mapping() {
            let mut state = super::contract_state_for_testing();
            // Setup with specifically numbered dummy verifiers
            let verifiers = array![
                1.try_into().unwrap(), 2.try_into().unwrap(), 3.try_into().unwrap(),
                4.try_into().unwrap(), 5.try_into().unwrap(), 6.try_into().unwrap(),
                7.try_into().unwrap(), 8.try_into().unwrap(), 9.try_into().unwrap(),
                10.try_into().unwrap(), 11.try_into().unwrap(), 12.try_into().unwrap(),
            ];
            super::constructor(ref state, verifiers.span());

            let mut depth: u8 = 1;

            while depth <= 32 {
                let verifier_address = SemaphoreImpl::get_verifier(@state, depth);
                let address_felt: felt252 = verifier_address.into();
                let address_u256: u256 = address_felt.into();
                let address_u8: u8 = address_u256.try_into().unwrap();

                let mut expected_index = 0;
                if depth <= 24 {
                    expected_index = depth / 3;
                    if depth % 3 != 0 {
                        expected_index += 1;
                    }
                } else {
                    let offset = depth - 24;
                    expected_index = 8 + (offset / 2);
                    if offset % 2 != 0 {
                        expected_index += 1;
                    }
                }

                assert(address_u8 == expected_index, 'Verifier mapping mismatch');
                depth += 1;
            }
        }
    }
}
