use alloy_consensus::{Header, ReceiptEnvelope};
use alloy_primitives::{BlockNumber, B256};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

use std::fs::File;
use std::io::{BufReader, BufWriter};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SmolBlock {
    pub header: Header,
    pub txs: Vec<B256>,
}

impl SmolBlock {
    pub fn new(header: Header, txs: Vec<B256>) -> Self {
        Self { header, txs }
    }

    fn bn(&self) -> u64 {
        self.header.number
    }
}

impl core::ops::Deref for SmolBlock {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Store {
    pub blocks: Vec<SmolBlock>,
    pub receipts: HashMap<BlockNumber, Vec<ReceiptEnvelope>>,
}
impl Store {
    /// Sort headers by block number
    pub fn sort_headers(&mut self) {
        self.blocks.sort_by_key(SmolBlock::bn);
    }
}

#[derive(Debug)]
pub struct Cache<P: AsRef<Path>> {
    pub store: Store,
    path: P,
}

impl<P: AsRef<Path>> Cache<P> {
    pub fn new(path: P) -> Self {
        let path_ref = path.as_ref();
        if !fs::exists(path_ref).unwrap() {
            return Self {
                path,
                store: Store::default(),
            };
        }
        let json = fs::read_to_string(path_ref)
            .unwrap_or_else(|err| panic!("Failed to load file: {:?}", err));
        let store = serde_json::from_str(&json).expect("Failed to parse json");
        Self { path, store }
    }

    pub fn save(&mut self) {
        use std::time::Instant;

        let start = Instant::now();
        self.store.sort_headers();
        let json = serde_json::to_string(&self.store).expect("Failed to serialize store");
        fs::write(self.path.as_ref(), json).expect("Writing failed");
        let elapsed = start.elapsed();

        info!("elapsed: {:?}", elapsed);
    }

    pub fn append_blocks(&mut self, headers: impl IntoIterator<Item = SmolBlock>) {
        self.store.blocks.extend(headers);
        self.store.sort_headers();
    }

    pub fn append_receipt(&mut self, bn: BlockNumber, receipt: ReceiptEnvelope) {
        self.store.receipts.entry(bn).or_default().push(receipt);
    }

    pub fn append_receipts(&mut self, bn: BlockNumber, receipts: Vec<ReceiptEnvelope>) {
        self.store.receipts.entry(bn).or_default().extend(receipts);
    }

    pub fn get_block(&self, bn: BlockNumber) -> Option<&SmolBlock> {
        self.store
            .blocks
            .binary_search_by_key(&bn, SmolBlock::bn)
            .ok()
            .map(|i| &self.store.blocks[i])
    }

    pub fn get_header_receipt_pair(
        &mut self,
        bn: BlockNumber,
    ) -> Option<(&mut Header, &mut Vec<ReceiptEnvelope>)> {
        let block_index = self
            .store
            .blocks
            .binary_search_by_key(&bn, SmolBlock::bn)
            .ok()?;
        let block = self.store.blocks.get_mut(block_index)?;
        let receipts = self.store.receipts.get_mut(&bn)?;

        Some((&mut block.header, receipts))
    }
}

impl<P: AsRef<Path>> core::ops::Deref for Cache<P> {
    type Target = Store;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl<P: AsRef<Path>> core::ops::DerefMut for Cache<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}
