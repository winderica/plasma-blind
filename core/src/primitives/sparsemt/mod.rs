// adapted from: https://github.com/arkworks-rs/ivls/blob/master/src/building_blocks/mt/merkle_sparse_tree/mod.rs

use std::collections::{BTreeMap, BTreeSet};

use ark_crypto_primitives::{
    Error,
    crh::{CRHScheme, TwoToOneCRHScheme, poseidon::TwoToOneCRH},
    merkle_tree::Config,
    sponge::Absorb,
};
use ark_ff::PrimeField;

pub mod constraints;

pub trait SparseConfig: Config<Leaf: Default> {
    const HEIGHT: usize;
}

pub struct MerkleSparseTree<P: SparseConfig> {
    pub tree: BTreeMap<usize, P::LeafDigest>,
    leaf_hash_params: <P::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_params: <P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    root: Option<P::InnerDigest>,
    empty_hashes: Vec<P::InnerDigest>,
}

impl<
    F: PrimeField + Absorb,
    P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
> MerkleSparseTree<P>
{
    /// obtain an empty tree
    pub fn blank(
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        let empty_hashes = gen_empty_hashes::<F, P>(
            leaf_hash_params,
            two_to_one_hash_params,
            &P::Leaf::default(),
            P::HEIGHT,
        )
        .unwrap();

        MerkleSparseTree {
            tree: BTreeMap::new(),
            leaf_hash_params: leaf_hash_params.clone(),
            two_to_one_hash_params: two_to_one_hash_params.clone(),
            root: Some(empty_hashes[(P::HEIGHT - 1) as usize]),
            empty_hashes,
        }
    }

    /// initialize a tree (with optional data)
    pub fn new(
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        leaves: &BTreeMap<usize, P::Leaf>,
    ) -> Result<Self, Error> {
        if leaves.len() == 0 {
            return Ok(Self::blank(leaf_hash_params, two_to_one_hash_params));
        }

        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_height = tree_height(tree_size);
        assert!(tree_height <= P::HEIGHT);

        // Initialize the merkle tree.
        let mut tree: BTreeMap<usize, P::InnerDigest> = BTreeMap::new();
        let empty_hashes = gen_empty_hashes::<F, P>(
            leaf_hash_params,
            two_to_one_hash_params,
            &P::Leaf::default(),
            P::HEIGHT,
        )?;

        // Compute and store the hash values for each leaf.
        let last_level_index = (1 << (P::HEIGHT - 1)) - 1;
        for (i, leaf) in leaves.iter() {
            tree.insert(
                last_level_index + *i,
                P::LeafHash::evaluate(leaf_hash_params, leaf)?,
            );
        }

        let mut middle_nodes: BTreeSet<usize> = BTreeSet::new();
        for i in leaves.keys() {
            middle_nodes.insert(parent(last_level_index + *i).unwrap());
        }

        // Compute the hash values for every node in parts of the tree.
        for level in 0..P::HEIGHT {
            // Iterate over the current level.
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let empty_hash = empty_hashes[level as usize];

                let left_hash = tree.get(&left_index).copied().unwrap_or(empty_hash);
                let right_hash = tree.get(&right_index).copied().unwrap_or(empty_hash);

                // Compute Hash(left || right).
                tree.insert(
                    *current_index,
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, &left_hash, &right_hash)?,
                );
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        let root_hash = tree[&0];

        Ok(MerkleSparseTree {
            tree,
            leaf_hash_params: leaf_hash_params.clone(),
            two_to_one_hash_params: two_to_one_hash_params.clone(),
            root: Some(root_hash),
            empty_hashes,
        })
    }

    #[inline]
    pub fn root(&self) -> P::InnerDigest {
        self.root.unwrap()
    }

    /// generate a membership proof (does not check the data point)
    pub fn generate_membership_proof(&self, index: usize) -> Result<Vec<P::InnerDigest>, Error> {
        self.siblings(index)
    }

    /// generate a lookup proof
    pub fn generate_proof(
        &self,
        index: usize,
        leaf: &P::Leaf,
    ) -> Result<Vec<P::InnerDigest>, Error> {
        let leaf_hash = P::LeafHash::evaluate(&self.leaf_hash_params, leaf)?;
        let tree_height = P::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Check that the given index corresponds to the correct leaf.
        if let Some(x) = self.tree.get(&tree_index) {
            assert_eq!(leaf_hash, *x);
        }

        self.generate_membership_proof(index)
    }

    /// update the tree and provide a modifying proof
    pub fn update_and_prove(
        &mut self,
        index: usize,
        new_leaf: &P::Leaf,
    ) -> Result<Vec<P::InnerDigest>, Error> {
        let siblings = self.siblings(index)?;

        let mut hash = P::LeafHash::evaluate(&self.leaf_hash_params, new_leaf)?;
        let mut index = convert_index_to_last_level(index, P::HEIGHT);

        for sibling in &siblings {
            self.tree.insert(index, hash);
            hash = if is_left_child(index) {
                P::TwoToOneHash::evaluate(&self.two_to_one_hash_params, &hash, sibling)?
            } else {
                P::TwoToOneHash::evaluate(&self.two_to_one_hash_params, sibling, &hash)?
            };
            index = parent(index).unwrap();
        }
        self.tree.insert(0, hash);
        self.root = Some(hash);

        Ok(siblings)
    }

    pub fn siblings(&self, index: usize) -> Result<Vec<F>, Error> {
        let mut siblings = vec![];

        let tree_height = P::HEIGHT;
        let mut index = convert_index_to_last_level(index, tree_height);

        for i in 0..tree_height - 1 {
            siblings.push(
                *self
                    .tree
                    .get(&sibling(index).unwrap())
                    .unwrap_or(&self.empty_hashes[i as usize]),
            );
            index = parent(index).unwrap();
        }

        Ok(siblings)
    }

    /// check if the tree is structurally valid
    pub fn validate(&self) -> Result<bool, Error> {
        /* Finding the leaf nodes */
        let last_level_index = (1 << (P::HEIGHT - 1)) - 1;
        let mut middle_nodes: BTreeSet<usize> = BTreeSet::new();

        for key in self.tree.keys() {
            if *key >= last_level_index && !is_root(*key) {
                middle_nodes.insert(parent(*key).unwrap());
            }
        }

        for level in 0..P::HEIGHT {
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = self.empty_hashes[level as usize];
                let mut right_hash = self.empty_hashes[level as usize];

                if self.tree.contains_key(&left_index) {
                    match self.tree.get(&left_index) {
                        Some(x) => left_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                if self.tree.contains_key(&right_index) {
                    match self.tree.get(&right_index) {
                        Some(x) => right_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                let hash = P::TwoToOneHash::evaluate(
                    &self.two_to_one_hash_params,
                    &left_hash,
                    &right_hash,
                )?;

                match self.tree.get(current_index) {
                    Some(x) => {
                        if *x != hash {
                            return Ok(false);
                        }
                    }
                    _ => {
                        return Ok(false);
                    }
                }
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        Ok(true)
    }
}

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: usize) -> usize {
    ark_std::log2(number) as usize
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: usize) -> usize {
    log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: usize) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: usize) -> usize {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: usize) -> usize {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: usize) -> Option<usize> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: usize) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: usize) -> Option<usize> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}

#[inline]
fn convert_index_to_last_level(index: usize, tree_height: usize) -> usize {
    index + (1 << (tree_height - 1)) - 1
}

fn gen_empty_hashes<
    F: PrimeField + Absorb,
    P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
>(
    leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    empty_leaf: &P::Leaf,
    n: usize,
) -> Result<Vec<P::InnerDigest>, Error> {
    let mut empty_hashes = Vec::with_capacity(n);
    let mut empty_hash = P::LeafHash::evaluate(leaf_hash_params, empty_leaf)?;
    empty_hashes.push(empty_hash);

    for _ in 1..=n {
        empty_hash = <P::TwoToOneHash as TwoToOneCRHScheme>::evaluate(
            two_to_one_hash_params,
            empty_hash,
            empty_hash,
        )?;
        empty_hashes.push(empty_hash);
    }

    Ok(empty_hashes)
}
