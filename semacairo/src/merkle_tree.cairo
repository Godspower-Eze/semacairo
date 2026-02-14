use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;

#[derive(Drop, Copy)]
struct MerkleTree {
    depth: u32,
    root: felt252,
}

// Calculates the generic Merkle root from a leaf and a proof path.
// proof_siblings: elements along the path to the root.
// path_indices: 0 (left) or 1 (right) for each level.
fn calculate_root(
    leaf: felt252, proof_siblings: Span<felt252>, path_indices: Span<bool>,
) -> felt252 {
    let mut current_hash = leaf;
    let mut i = 0;
    let depth = proof_siblings.len();

    while i < depth {
        let sibling = *proof_siblings.at(i);
        let is_right_node = *path_indices.at(i);

        let mut input_array = ArrayTrait::new();
        if is_right_node {
            // current_hash is the right child
            input_array.append(sibling);
            input_array.append(current_hash);
        } else {
            // current_hash is the left child
            input_array.append(current_hash);
            input_array.append(sibling);
        }

        current_hash = poseidon_hash_span(input_array.span());
        i += 1;
    }

    current_hash
}

// Confirms if a leaf exists in the tree with the given root.
fn verify(
    root: felt252, leaf: felt252, proof_siblings: Span<felt252>, path_indices: Span<bool>,
) -> bool {
    let calculated = calculate_root(leaf, proof_siblings, path_indices);
    calculated == root
}

#[derive(Drop, Copy)]
pub struct FrontierUpdate {
    pub level: u8,
    pub node: felt252,
}

// Inserts a leaf into the incremental Merkle Tree given the current size and frontier.
// Returns the new root and a list of updates to the frontier.
// frontier: Span of nodes where frontier[i] is the node at level i.
// zero_values: Span of zero values for each level.
pub fn insert(
    leaf: felt252,
    depth: u32,
    current_size: u256,
    frontier: Span<felt252>,
    zero_values: Span<felt252>,
) -> (felt252, Array<FrontierUpdate>) {
    let mut current_index = current_size;
    let mut current_level_hash = leaf;
    let mut updates = ArrayTrait::new();

    let mut i: u32 = 0;
    while i < depth {
        // maximize safety with u8 cast if needed, but loop uses u32
        let level_u8: u8 = i.try_into().unwrap();

        let is_right_node = (current_index % 2) == 1;

        let mut input = ArrayTrait::new();

        if is_right_node {
            // Right node. Left is in frontier.
            // Safety check: frontier must have enough elements.
            // If frontier is sparse or missing, we assume 0? No, should be passed correctly.
            // We assume the caller passes a frontier that covers up to depth.
            // Or at least up to the current needed level.
            let left = *frontier.at(i);
            input.append(left);
            input.append(current_level_hash);

            current_level_hash = poseidon_hash_span(input.span());
        } else {
            // Left node. Right is zero.
            // Store ourselves in the frontier.
            updates.append(FrontierUpdate { level: level_u8, node: current_level_hash });

            let zero = *zero_values.at(i);
            input.append(current_level_hash);
            input.append(zero);

            current_level_hash = poseidon_hash_span(input.span());
        }

        current_index = current_index / 2;
        i += 1;
    }

    let root = current_level_hash;

    (root, updates)
}

#[cfg(test)]
mod tests {
    use core::array::ArrayTrait;
    use core::poseidon::poseidon_hash_span;
    use super::{FrontierUpdate, calculate_root, insert, verify};

    #[test]
    fn test_merkle_root_calculation() {
        // Leaves: L1=1, L2=2, L3=3, L4=4
        let leaf_1 = 1;
        let leaf_2 = 2; // Right of L1
        let leaf_3 = 3;
        let leaf_4 = 4;

        // H1 = hash(1, 2)
        let mut h1_input = ArrayTrait::new();
        h1_input.append(leaf_1);
        h1_input.append(leaf_2);
        let h1 = poseidon_hash_span(h1_input.span());

        // H2 = hash(3, 4)
        let mut h2_input = ArrayTrait::new();
        h2_input.append(leaf_3);
        h2_input.append(leaf_4);
        let h2 = poseidon_hash_span(h2_input.span());

        // Root = hash(H1, H2)
        let mut root_input = ArrayTrait::new();
        root_input.append(h1);
        root_input.append(h2);
        let expected_root = poseidon_hash_span(root_input.span());

        // Proof for L1: [L2, H2]
        let mut proof = ArrayTrait::new();
        proof.append(leaf_2);
        proof.append(h2);

        // Indices: L1 is left (false), H1 is left (false)
        let mut indices = ArrayTrait::new();
        indices.append(false);
        indices.append(false);

        let calculated = calculate_root(leaf_1, proof.span(), indices.span());
        assert(calculated == expected_root, 'Root calculation failed');

        assert(verify(expected_root, leaf_1, proof.span(), indices.span()), 'Verify failed');
    }

    #[test]
    fn test_incremental_insert() {
        let mut zero_values = ArrayTrait::new();
        let z0 = 0;
        zero_values.append(z0);

        let mut input0 = ArrayTrait::new();
        input0.append(z0);
        input0.append(z0);
        let z1 = poseidon_hash_span(input0.span());
        zero_values.append(z1);

        let zeros = zero_values.span();

        let depth = 2;

        let mut frontier = ArrayTrait::new();
        frontier.append(0);
        frontier.append(0);

        let leaf1 = 1;
        let size = 0;
        let (_root1, updates1) = insert(leaf1, depth, size, frontier.span(), zeros);

        let updates1_span = updates1.span();
        assert(updates1_span.len() == 2, 'Should have 2 updates');

        let up_box = updates1_span.at(0);
        let up: FrontierUpdate = *up_box;
        assert(up.level == 0, 'Level should be 0');
        assert(up.node == leaf1, 'Node should be leaf1');

        let up_box1 = updates1_span.at(1);
        let up1: FrontierUpdate = *up_box1;
        assert(up1.level == 1, 'Level should be 1');
        let mut input1 = ArrayTrait::new();
        input1.append(1);
        input1.append(z0);
        let z2 = poseidon_hash_span(input1.span());
        assert(up1.node == z2, 'Node should be z2');

        let mut frontier_arr = ArrayTrait::new();
        frontier_arr.append(leaf1);
        frontier_arr.append(0);

        let leaf2 = 2;
        let size2 = 1;
        let (root2, updates2) = insert(leaf2, depth, size2, frontier_arr.span(), zeros);

        let updates2_span = updates2.span();
        assert(updates2_span.len() == 1, 'Should have 1 update');

        let up2_box = updates2_span.at(0);
        let up2: FrontierUpdate = *up2_box;
        assert(up2.level == 1, 'Level should be 1');

        let mut h1_in = ArrayTrait::new();
        h1_in.append(leaf1);
        h1_in.append(leaf2);
        let h1 = poseidon_hash_span(h1_in.span());

        assert(up2.node == h1, 'Node should be h1');

        let mut r_in = ArrayTrait::new();
        r_in.append(h1);
        r_in.append(z1);
        let expected_root2 = poseidon_hash_span(r_in.span());

        assert(root2 == expected_root2, 'Root2 mismatch');
    }
}
