//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::keccak256;
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

        keccak.update(header);
        keccak.finalize_and_reset(&mut last_hash);
        // last_hash.copy_from_slice(keccak256(&header).as_slice());
    };

    while !reader.is_empty() {
        let header = EncodedHeaderLens::read_from(&mut reader).unwrap();
        assert_eq!(&last_hash, header.parent_hash(), "Broken parent-child-link");

        keccak.update(header);
        keccak.finalize_and_reset(&mut last_hash);
        // last_hash.copy_from_slice(keccak256(&header).as_slice());
    }

    out.extend_from_slice(last_hash.as_slice());

    sp1_zkvm::io::commit_slice(&out);
}
