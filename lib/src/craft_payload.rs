use crate::fee_summary::FeeEntry;
use crate::receipt_trie::get_proof_for_receipt;
use alloy_consensus::{Header, ReceiptEnvelope};
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct RewardBlock {
    pub block_index: u32,
    pub proof: Vec<u8>,
    pub receipt: ReceiptEnvelope,
    pub log_index: u32,
    pub fee_entries: Vec<FeeEntry>,
}

#[derive(Clone, Debug)]
pub struct Payload {
    pub headers: Vec<u8>,
    pub reward_blocks: Vec<RewardBlock>,
}

pub fn build_payload(
    blocks: Vec<(Header, Option<Vec<ReceiptEnvelope>>)>,
    angstrom: Address,
    fee_summary_oracle: &BTreeMap<B256, Vec<FeeEntry>>,
) -> Payload {
    let mut headers = Vec::new();
    let mut reward_blocks = Vec::new();

    for ((header, receipts), block_index) in blocks.into_iter().zip(0..) {
        header.encode(&mut headers);
        if let Some(receipts) = receipts {
            let (receipt, receipt_index, reward_hash, log_index) = receipts
                .iter()
                .zip(0..)
                .find_map(|(receipt, receipt_index)| {
                    receipt.logs().iter().zip(0..).find_map(|(log, log_index)| {
                        if log.address != angstrom {
                            return None;
                        }
                        let reward_hash = B256::try_from(&log.data.data[0..32]).unwrap();
                        Some((receipt, receipt_index, reward_hash, log_index))
                    })
                })
                .expect("Receipt list without reward log");

            reward_blocks.push(RewardBlock {
                block_index,
                proof: get_proof_for_receipt(receipts.as_slice(), receipt_index),
                receipt: receipt.clone(),
                log_index: log_index.try_into().unwrap(),
                fee_entries: fee_summary_oracle
                    .get(&reward_hash)
                    .expect("Missing fee summary oracle entry")
                    .clone(),
            })
        }
    }

    Payload {
        headers,
        reward_blocks,
    }
}
