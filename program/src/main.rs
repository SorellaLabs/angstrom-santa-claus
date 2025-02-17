//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use santa_lib::{header_lens::EncodedHeaderLens, Keccak256 as SantaKeccak256, Reader};
use sha3::{Digest, Keccak256 as Sha3Keccak256};

trait SimpleHash {
    fn init() -> Self;
    fn s_update(&mut self, input: impl AsRef<[u8]>);

    fn finish(&mut self, out: &mut [u8; 32]);
}

impl SimpleHash for Sha3Keccak256 {
    fn init() -> Self {
        Self::new()
    }

    fn s_update(&mut self, input: impl AsRef<[u8]>) {
        self.update(input);
    }

    fn finish(&mut self, out: &mut [u8; 32]) {
        self.finalize_into_reset(out.into());
    }
}

impl SimpleHash for SantaKeccak256 {
    fn init() -> Self {
        Self::default()
    }
    fn s_update(&mut self, input: impl AsRef<[u8]>) {
        self.update(input);
    }

    fn finish(&mut self, out: &mut [u8; 32]) {
        self.finalize_and_reset(out);
    }
}

pub fn main() {
    let headers = sp1_zkvm::io::read_vec();
    let mut reader = Reader::from(headers.as_slice());

    let mut out = Vec::with_capacity(64);

    let mut keccak = SantaKeccak256::init();

    let mut last_hash = [0u8; 32];
    {
        let header = EncodedHeaderLens::read_from(&mut reader).unwrap();
        out.extend_from_slice(header.parent_hash());
        keccak.s_update(header);
        keccak.finish(&mut last_hash);
    };

    while !reader.is_empty() {
        let header = EncodedHeaderLens::read_from(&mut reader).unwrap();
        assert_eq!(&last_hash, header.parent_hash(), "Broken parent-child-link");

        keccak.s_update(header);
        keccak.finish(&mut last_hash);
    }

    out.extend_from_slice(last_hash.as_slice());

    sp1_zkvm::io::commit_slice(&out);
}
