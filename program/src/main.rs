//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_consensus::Header;
use alloy_primitives::{hex, Bytes, B256};
use alloy_rlp::Decodable;
use alloy_trie::{proof::verify_proof, Nibbles};
// use santa_lib::receipt_trie::receipt_trie_root_from_proof;
use santa_lib::{header_lens::EncodedHeaderLens, Keccak256, Reader};

pub fn main() {
    let headers = sp1_zkvm::io::read_vec();
    let mut reader = Reader::from(headers.as_slice());

    let mut out = Vec::with_capacity(64);

    let mut keccak = Keccak256::default();
    let mut last_hash = [0u8; 32];

    {
        let header = EncodedHeaderLens::read_from(&mut reader).unwrap();
        out.extend_from_slice(header.parent_hash());
        keccak.complete(&header, &mut last_hash);
    }

    while !reader.is_empty() {
        let header = EncodedHeaderLens::read_from(&mut reader).unwrap();
        assert_eq!(&last_hash, header.parent_hash(), "Broken parent-child-link");

        keccak.complete(&header, &mut last_hash);
    }

    out.extend_from_slice(last_hash.as_slice());

    sp1_zkvm::io::commit_slice(&out);
}

// fn alloy_verify(receipt: Vec<u8>, root: B256) -> bool {
//     let key = Nibbles::from_vec(sp1_zkvm::io::read_vec());

//     let total_bytes = sp1_zkvm::io::read_vec();
//     let total_elements = u16::from_le_bytes([unsafe { *total_bytes.get_unchecked(1) }, unsafe {
//         *total_bytes.get_unchecked(0)
//     }]);

//     let mut proof: Vec<Bytes> = Vec::with_capacity(total_elements as usize);
//     for _ in 0..total_elements {
//         proof.push(Bytes::from(sp1_zkvm::io::read_vec()));
//     }
//     verify_proof(root, key, Some(receipt), proof.iter()).is_ok()
// }

// fn santa_verify(receipt: Vec<u8>, root: B256) -> bool {
//     let proof = sp1_zkvm::io::read_vec();
//     receipt_trie_root_from_proof(proof, receipt) == root
// }
