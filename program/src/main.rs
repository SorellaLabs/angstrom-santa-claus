//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::hex;
use alloy_primitives::{Address, U256};
use santa_lib::{
    fee_summary::{FeeSummaryInspector, FEE_ENTRY_SIZE},
    header_lens::EncodedHeaderLens,
    payload::{Payload, RewardBlock},
    receipt_trie::receipt_trie_root_from_proof,
    Keccak256, Reader,
};
use std::collections::HashMap;

pub fn main() {
    let payload = sp1_zkvm::io::read();
    let (chain_parent, chain_last, sums) = validate_payload(&payload);

    let mut out = Vec::with_capacity(20 + 32 + 32 + (20 + 32) * sums.len());

    out.extend_from_slice(payload.angstrom.as_slice());
    out.extend_from_slice(&chain_parent);
    out.extend_from_slice(&chain_last);

    for (addr, amount) in sums {
        out.extend_from_slice(addr.as_slice());
        out.extend_from_slice(&amount.to_be_bytes::<32>());
    }

    sp1_zkvm::io::commit_slice(&out);
}

struct RewardAggregator<'p> {
    sums: HashMap<Address, U256>,
    fee_entry_offset: usize,
    block_index: u32,
    reward_blocks: std::iter::Peekable<std::slice::Iter<'p, RewardBlock>>,
    payload: &'p Payload,
    encoded_receipt_buf: Vec<u8>,
}

impl<'p> RewardAggregator<'p> {
    fn new(payload: &'p Payload) -> Self {
        Self {
            sums: HashMap::with_capacity(32),
            fee_entry_offset: 0,
            block_index: 0,
            reward_blocks: payload.reward_blocks.iter().peekable(),
            payload,
            encoded_receipt_buf: Vec::with_capacity(512),
        }
    }

    fn validate_and_agg_next_block(
        &mut self,
        header: &EncodedHeaderLens,
        hash_out: &mut [u8; 32],
        keccak: &mut Keccak256,
    ) {
        let block_index = self.block_index;
        self.block_index += 1;

        let rb = if let Some(rb) = self
            .reward_blocks
            .next_if(|rb| rb.block_index == block_index)
        {
            rb
        } else {
            return;
        };

        let log = &rb.receipt.logs()[rb.log_index as usize];
        assert!(log.address == self.payload.angstrom);

        let fee_entry_offset = self.fee_entry_offset;

        let block_fee_entries = rb.fee_entries as usize;
        self.fee_entry_offset += block_fee_entries;
        let fee_summaries = FeeSummaryInspector::try_from(
            &self.payload.fee_entries[fee_entry_offset * FEE_ENTRY_SIZE
                ..(fee_entry_offset + block_fee_entries) * FEE_ENTRY_SIZE],
        )
        .unwrap();
        keccak.update(fee_summaries);
        keccak.finalize_and_reset(hash_out);
        assert_eq!(hash_out, &log.data.data[..]);

        self.encoded_receipt_buf.clear();
        rb.receipt.encode_2718(&mut self.encoded_receipt_buf);

        let computed_receipt_root =
            receipt_trie_root_from_proof(keccak, &rb.proof, &self.encoded_receipt_buf);
        assert_eq!(computed_receipt_root, header.receipts_root());

        for i in 0..block_fee_entries {
            let entry = fee_summaries[i];
            let amount = entry.amount();
            if amount > 0 {
                *self.sums.entry(*entry.asset()).or_default() += U256::from(amount);
            }
        }
    }

    fn into_sums(self) -> HashMap<Address, U256> {
        self.sums
    }
}

fn validate_payload(payload: &Payload) -> ([u8; 32], [u8; 32], HashMap<Address, U256>) {
    let mut keccak = Keccak256::default();
    let mut chain_parent = [0u8; 32];

    let mut headers = Reader::from(payload.headers.as_slice());
    let mut reward_agg = RewardAggregator::new(&payload);

    // Read first header, store parent as start of chain and compute hash.
    let mut last_hash = {
        let header = EncodedHeaderLens::read_from(&mut headers).unwrap();
        chain_parent.copy_from_slice(header.parent_hash());

        let mut hash_out = [0u8; 32];

        reward_agg.validate_and_agg_next_block(&header, &mut hash_out, &mut keccak);

        keccak.update(header);
        keccak.finalize_and_reset(&mut hash_out);
        hash_out
    };

    while !headers.is_empty() {
        let header = EncodedHeaderLens::read_from(&mut headers).unwrap();
        assert_eq!(&last_hash, header.parent_hash(), "Broken parent-child-link");

        // Can use `last_hash` as hash out because it's value was already used and is going to be
        // overwritten.
        reward_agg.validate_and_agg_next_block(&header, &mut last_hash, &mut keccak);

        keccak.update(header);
        keccak.finalize_and_reset(&mut last_hash);
    }

    (chain_parent, last_hash, reward_agg.into_sums())
}
