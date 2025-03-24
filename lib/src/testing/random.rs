use crate::fee_summary::FeeEntry;
use alloy_consensus::{proofs::calculate_receipt_root, Header, ReceiptEnvelope};
use alloy_primitives::{keccak256, Address, Log, B256};
use rand::{
    distr::{Bernoulli, Distribution},
    Rng,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct LogInjector {
    angstrom: Address,
    possible_assets: Vec<Address>,
    rng: rand::rngs::ThreadRng,
    solo: Bernoulli,
    hash_to_entry_oracle: BTreeMap<B256, Box<[FeeEntry]>>,
}

impl LogInjector {
    pub fn new(angstrom: Address, mut possible_assets: Vec<Address>, solo_log_prob: f32) -> Self {
        possible_assets.sort();

        Self {
            angstrom,
            possible_assets,
            rng: rand::rng(),
            solo: Bernoulli::new(solo_log_prob.into()).expect("Failed to initialize bernouli"),
            hash_to_entry_oracle: BTreeMap::new(),
        }
    }

    fn random_log(&mut self) -> Log {
        let mut entries = Vec::with_capacity(self.possible_assets.len());

        for addr in self.possible_assets.iter() {
            if self.rng.random() {
                continue;
            }
            entries.push(FeeEntry::new(*addr, self.rng.random()));
        }

        let hash = keccak256(entries.concat());
        self.hash_to_entry_oracle
            .insert(hash, entries.into_boxed_slice());

        let data = hash.into();

        Log::new(self.angstrom, vec![], data).unwrap()
    }

    pub fn inject_random_summaries(
        &mut self,
        header: &mut Header,
        receipts: &mut Vec<ReceiptEnvelope>,
    ) {
        let i = self.rng.random_range(0..receipts.len());
        match &mut receipts[i] {
            ReceiptEnvelope::Legacy(r)
            | ReceiptEnvelope::Eip2930(r)
            | ReceiptEnvelope::Eip1559(r)
            | ReceiptEnvelope::Eip4844(r)
            | ReceiptEnvelope::Eip7702(r) => {
                let r = &mut r.receipt;
                r.status = true.into();
                if r.logs.is_empty() || self.solo.sample(&mut self.rng) {
                    r.logs = vec![self.random_log()];
                } else {
                    let li = self.rng.random_range(0..r.logs.len());
                    r.logs[li] = self.random_log();
                }
            }
        }
        header.receipts_root = calculate_receipt_root(receipts.as_slice());
    }

    pub fn into_oracle(self) -> BTreeMap<B256, Box<[FeeEntry]>> {
        self.hash_to_entry_oracle
    }
}
