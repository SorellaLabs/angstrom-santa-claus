use crate::Reader;
use alloy_eips::Encodable2718;
use alloy_primitives::{hex, Bytes, Keccak256, B256};
use alloy_rlp::{encode_fixed_size, length_of_length, Encodable, Rlp};
use alloy_trie::{
    proof::ProofNodes, proof::ProofRetainer, root::adjust_index_for_rlp, HashBuilder, Nibbles,
};

fn hash_and_get_proof_nodes<R>(items: &[R], index: u32) -> ProofNodes
where
    R: Encodable2718,
{
    assert!((index as usize) < items.len());

    let mut value_buffer = Vec::new();

    let retainer = {
        let mut encoded_index_buffer = Vec::<u8>::new();
        index.encode(&mut encoded_index_buffer);
        ProofRetainer::new(vec![Nibbles::unpack(encoded_index_buffer)])
    };
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);

    // hb.with_proof_retainer(Proo)

    let items_len = items.len();
    for i in 0..items_len {
        let index = adjust_index_for_rlp(i, items_len);

        let index_buffer = encode_fixed_size(&index);

        value_buffer.clear();
        items[index].encode_2718(&mut value_buffer);

        hb.add_leaf(Nibbles::unpack(&index_buffer), &value_buffer);
    }

    hb.root();

    hb.take_proof_nodes()
}

fn rlp_decode(payload: &[u8]) -> alloy_rlp::Result<Vec<Bytes>> {
    let mut view = Rlp::new(payload)?;
    let mut list = vec![];

    while let Some(next) = view.get_next()? {
        list.push(next);
    }

    Ok(list)
}

pub fn get_proof_for_receipt<R>(items: &[R], index: u32) -> Vec<u8>
where
    R: Encodable2718,
{
    let proof_nodes = hash_and_get_proof_nodes(items, index);
    let mut proof_steps = proof_nodes.into_inner().into_iter().collect::<Vec<_>>();
    proof_steps.sort_by_key(|(key, _)| std::cmp::Reverse(key.len()));

    let leaf_path = {
        let (_, full_bytes) = &proof_steps[0];
        let mut as_list = rlp_decode(full_bytes).unwrap();
        as_list.swap_remove(0)
    };
    let mut proof_builder = ProofBuilder::with_leaf_rest_path_compact(leaf_path);

    let index_as_key = Nibbles::unpack({
        let mut buf = Vec::<u8>::new();
        index.encode(&mut buf);
        buf
    });

    proof_steps[1..].iter().for_each(|(key, value)| {
        let as_list = rlp_decode(value).unwrap();
        if as_list.len() == 2 {
            proof_builder.add_extension(&as_list[0]);
        } else {
            assert_eq!(as_list.len(), 17, "Expected branch");
            let index = index_as_key[key.len()];
            proof_builder.add_branch(index, as_list);
        }
    });

    proof_builder.build()
}

const RLP_STR_OFFSET: u8 = 0x80;
const RLP_LIST_OFFSET: u8 = 0xc0;

const PATH_FLAG_MASK: u8 = 0x20;
const LEAF_PATH_FLAG: u8 = 0x20;
const EXTENSION_PATH_FLAG: u8 = 0x00;
const ODD_NIBBLES_FLAG: u8 = 0x10;
const NIBBLE_MASK: u8 = 0xf;

const fn encoded_length(payload_length: usize) -> usize {
    length_of_length(payload_length) + payload_length
}

/*
struct Keccak256Debug(Vec<u8>);

impl Keccak256Debug {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.0.extend_from_slice(bytes.as_ref());
    }

    fn finalize(self) -> B256 {
        let out = alloy_primitives::keccak256(&self.0);

        println!("  [hashing] {} -> {}", hex::encode(self.0), out);

        out
    }
}
*/

type Keccak = Keccak256; // To be swapped out when debugging

fn encode_header(hasher: &mut Keccak, offset: u8, payload_length: usize) {
    if payload_length < 56 {
        let head_byte = offset + payload_length as u8;
        hasher.update([head_byte]);
    } else {
        let length_bytes_length: usize = length_of_length(payload_length) - 1;
        let head_byte = offset + 55 + length_bytes_length as u8;
        hasher.update([head_byte]);

        let bytes = payload_length.to_be_bytes();
        hasher.update(&bytes[(usize::BITS / 8) as usize - length_bytes_length..]);

        // for i in 0..length_bytes_length {
        //     let i = length_bytes_length - i - 1;
        //     let byte = ((payload_length >> (i * 8)) & 0xff) as u8;
        //     hasher.update([byte]);
        // }
    }
}

fn encode_list_header(hasher: &mut Keccak, payload_length: usize) {
    encode_header(hasher, RLP_LIST_OFFSET, payload_length)
}

fn encode_str_header(hasher: &mut Keccak, payload_length: usize) {
    encode_header(hasher, RLP_STR_OFFSET, payload_length)
}

fn hash_node_with_path(proof: &mut Reader, path_flag: u8, encoded_internal_node: &[u8]) -> B256 {
    // Determine length of encoded key.
    let leaf_key_nibbles = proof.read_byte();
    let key_bytes = leaf_key_nibbles as usize / 2;
    let encoded_key_length = encoded_length(key_bytes + 1) - (key_bytes == 0) as usize;

    let encoded_receipt_length = encoded_length(encoded_internal_node.len());

    // Push head.
    let rlp_list_payload_length = encoded_key_length + encoded_receipt_length;
    let mut hasher = Keccak::new();
    encode_list_header(&mut hasher, rlp_list_payload_length);

    // Push key
    let first_byte = if leaf_key_nibbles % 2 == 0 {
        path_flag
    } else {
        let odd_nibble = proof.read_byte() & NIBBLE_MASK;
        path_flag | ODD_NIBBLES_FLAG | odd_nibble
    };
    if key_bytes >= 1 || first_byte > 0x7f || first_byte == 0 {
        encode_str_header(&mut hasher, key_bytes + 1);
    }
    hasher.update([first_byte]);
    hasher.update(proof.read_next(key_bytes));

    // Push receipt
    encode_str_header(&mut hasher, encoded_internal_node.len());
    hasher.update(encoded_internal_node);

    hasher.finalize()
}

fn hash_leaf(proof: &mut Reader, encoded_receipt: &[u8]) -> B256 {
    hash_node_with_path(proof, LEAF_PATH_FLAG, encoded_receipt)
}

fn hash_extension(proof: &mut Reader, encoded_receipt: &[u8]) -> B256 {
    hash_node_with_path(proof, EXTENSION_PATH_FLAG, encoded_receipt)
}

/// Computes the hash of a branch node with one hash of a previous node, assumes that all other
/// paths are either empty or themselves 32-byte hashes.
fn hash_branch(proof: &mut Reader, weird_branches: bool, index: u8, last_root: &[u8]) -> B256 {
    let branch_map: u16 = u16::from_be_bytes([proof.read_byte(), proof.read_byte()]);

    let mut hasher = Keccak::new();

    let payload_length = if weird_branches {
        u32::from_be_bytes([
            proof.read_byte(),
            proof.read_byte(),
            proof.read_byte(),
            proof.read_byte(),
        ])
        .try_into()
        .unwrap()
    } else {
        TryInto::<usize>::try_into(branch_map.count_ones()).unwrap() * 32 + 17
    };

    encode_list_header(&mut hasher, payload_length);

    for i in 0..index {
        if branch_map & (1 << i) == 0 {
            encode_str_header(&mut hasher, 0);
        } else {
            encode_str_header(&mut hasher, 32);
            hasher.update(proof.read_next(32));
        }
    }
    encode_str_header(&mut hasher, 32);
    hasher.update(last_root);

    for i in index + 1..16 {
        if branch_map & (1 << i) == 0 {
            encode_str_header(&mut hasher, 0);
        } else if weird_branches {
            let payload_length = u32::from_be_bytes([
                proof.read_byte(),
                proof.read_byte(),
                proof.read_byte(),
                proof.read_byte(),
            ])
            .try_into()
            .unwrap();
            encode_str_header(&mut hasher, payload_length);
            hasher.update(proof.read_next(payload_length));
        } else {
            encode_str_header(&mut hasher, 32);
            hasher.update(proof.read_next(32));
        }
    }

    // Empty branch node value.
    encode_str_header(&mut hasher, 0);

    hasher.finalize()
}

const PROOF_PART_TYPE_MASK: u8 = 0x20u8;
const EXTENSION_NODE_FLAG: u8 = 0x00u8;
const BRANCH_NODE_FLAG: u8 = 0x20u8;
const WEIRD_BRANCHES_FLAG: u8 = 0x10u8;
const BRANCH_NODE_INDEX_MASK: u8 = 0x0fu8;

pub fn receipt_trie_root_from_proof(
    proof: impl AsRef<[u8]>,
    encoded_receipt: impl AsRef<[u8]>,
) -> B256 {
    let mut proof = Reader::from(proof.as_ref());
    let mut current_root = hash_leaf(&mut proof, encoded_receipt.as_ref());

    while !proof.is_empty() {
        let control_byte = proof.read_byte();
        if control_byte & PROOF_PART_TYPE_MASK == BRANCH_NODE_FLAG {
            let index = control_byte & BRANCH_NODE_INDEX_MASK;
            current_root = hash_branch(
                &mut proof,
                control_byte & WEIRD_BRANCHES_FLAG != 0,
                index,
                current_root.as_slice(),
            );
        } else {
            current_root = hash_extension(&mut proof, current_root.as_slice());
        }
    }

    current_root
}

#[derive(Debug, Clone)]
struct TriePath<'a>(&'a [u8]);

impl<'a> std::ops::Deref for TriePath<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> TriePath<'a> {
    fn new(path: &'a [u8]) -> Self {
        assert!(path.len() >= 1, "Path must be at least 1 byte long");
        let new_path = Self(path);
        assert!(
            new_path.nibbles() <= 64,
            "Path must be at most 64 nibbles long"
        );
        new_path
    }

    fn is_odd(&self) -> bool {
        self.0[0] & ODD_NIBBLES_FLAG != 0
    }

    fn is_leaf(&self) -> bool {
        self.0[0] & PATH_FLAG_MASK == LEAF_PATH_FLAG
    }

    fn is_extension(&self) -> bool {
        self.0[0] & PATH_FLAG_MASK == EXTENSION_PATH_FLAG
    }

    /// Total nibbles in path
    fn nibbles(&self) -> u8 {
        (self.len() as u8 - 1) * 2 + self.is_odd() as u8
    }

    /// Total bytes in path
    fn bytes(&self) -> u8 {
        (self.len() as u8 - 1) + self.is_odd() as u8
    }

    fn write_bytes(&self, buf: &mut Vec<u8>) {
        if self.is_odd() {
            buf.push(self.0[0] & NIBBLE_MASK);
        }
        buf.extend_from_slice(&self[1..]);
    }
}

#[derive(Debug, Clone)]
pub struct ProofBuilder(Vec<u8>);

impl ProofBuilder {
    pub fn with_leaf_rest_path_compact(path: impl AsRef<[u8]>) -> Self {
        let path = TriePath::new(path.as_ref());
        assert!(path.is_leaf(), "Not leaf path but extension node path");

        let mut leaf = Vec::with_capacity(1 + path.bytes() as usize);
        leaf.push(path.nibbles());
        path.write_bytes(&mut leaf);
        Self(leaf)
    }

    pub fn add_extension(&mut self, path: impl AsRef<[u8]>) {
        let path = path.as_ref();
        let path = TriePath::new(path.as_ref());
        assert!(path.is_extension(), "Expected extension path");

        self.push(EXTENSION_NODE_FLAG);
        self.push(path.nibbles());
        path.write_bytes(self);
    }

    pub fn add_branch<B: AsRef<[u8]>>(&mut self, index: u8, nodes: impl AsRef<[B]>) {
        assert!(index <= 15, "Not nibble: {}", index);
        let nodes = nodes.as_ref();

        let mut branch_map = 0u16;
        for (i, node) in nodes.iter().enumerate() {
            if node.as_ref().len() == 32 {
                branch_map |= 1 << i;
            } else {
                assert!(
                    node.as_ref().len() == 0,
                    "Weird branches where nodes are not empty/hashes is not currently supported"
                );
            }
        }

        self.push(BRANCH_NODE_FLAG | index);
        self.extend_from_slice(&branch_map.to_be_bytes());

        nodes
            .iter()
            .enumerate()
            .filter(|(i, node)| *i != index as usize && node.as_ref().len() == 32)
            .for_each(|(_, node)| {
                self.extend_from_slice(node.as_ref());
            });
    }

    pub fn build(self) -> Vec<u8> {
        self.0
    }
}

impl std::ops::Deref for ProofBuilder {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ProofBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
