use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, Bloom, B256};
use alloy_rlp::{Decodable, Encodable, Header as RLPHeader};

/// Partially encoded ethereum block header. Has un-encoded fields up to `logs_bloom`, the
/// remaining fields are stored in their RLP encoded form in `encoded_tail`. Assuming Ethereum
/// maintains its convention of only adding new fields to the end of headers this should remain
/// foreward-compatible well into the future.
#[derive(Debug, Clone)]
pub struct PartialHeader<T: AsRef<[u8]>> {
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub beneficiary: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub encoded_tail: T,
}

impl<T: AsRef<[u8]>> AsRef<PartialHeader<T>> for PartialHeader<T> {
    fn as_ref(&self) -> &PartialHeader<T> {
        self
    }
}

impl<T: AsRef<[u8]>> PartialHeader<T> {
    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length();
        length += self.ommers_hash.length();
        length += self.beneficiary.length();
        length += self.state_root.length();
        length += self.transactions_root.length();
        length += self.receipts_root.length();
        length += self.logs_bloom.length();
        length += self.encoded_tail.as_ref().len();
        length
    }

    pub fn hash(&self) -> B256 {
        let mut buf = Vec::with_capacity(self.header_payload_length());
        self.encode(&mut buf);
        keccak256(buf)
    }
}

impl PartialHeader<Box<[u8]>> {
    pub fn partially_decode(full_buf: impl AsRef<[u8]>) -> alloy_rlp::Result<Self> {
        let buf = &mut full_buf.as_ref();

        let rlp_head = RLPHeader::decode(buf)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        Ok(Self {
            parent_hash: Decodable::decode(buf)?,
            ommers_hash: Decodable::decode(buf)?,
            beneficiary: Decodable::decode(buf)?,
            state_root: Decodable::decode(buf)?,
            transactions_root: Decodable::decode(buf)?,
            receipts_root: Decodable::decode(buf)?,
            logs_bloom: Decodable::decode(buf)?,
            encoded_tail: (*buf).into(),
        })
    }
}

impl<T: AsRef<[u8]>> Encodable for PartialHeader<T> {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let list_header = RLPHeader {
            list: true,
            payload_length: self.header_payload_length(),
        };
        list_header.encode(out);
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        out.put_slice(self.encoded_tail.as_ref());
    }

    fn length(&self) -> usize {
        let inner_length = self.header_payload_length();
        inner_length + alloy_rlp::length_of_length(inner_length)
    }
}

impl<H: AsRef<Header>> From<H> for PartialHeader<Box<[u8]>> {
    fn from(header: H) -> Self {
        let header = header.as_ref();
        let mut encoded = Vec::with_capacity(header.length());
        // It's inefficient to encode the full header just to decode it but it helps us avoid
        // maintaining a duplicate of alloy's `Header::encode`.
        header.encode(&mut encoded);
        Self::partially_decode(&mut encoded)
            .unwrap_or_else(|_| panic!("Failed to partially decode header that was just encoded"))
    }
}
