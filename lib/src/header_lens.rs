use crate::rlp::*;
use crate::Reader;
use alloy_primitives::{keccak256, B256};
use std::ops::Deref;

/// Tracks an already RLP encoded, partially validated header. Only validates that the encoding is
/// valid up to the `receipts_root` field.
#[derive(Debug, Clone)]
pub struct EncodedHeaderLens<'a> {
    encoded: &'a [u8],
    payload_offset: usize,
}

impl<'a> EncodedHeaderLens<'a> {
    pub fn hash(&self) -> B256 {
        keccak256(self)
    }

    pub fn read_from(reader: &mut Reader<'a>) -> Result<Self, String> {
        let head = reader[0];
        let length_bytes = if head > RLP_LIST_OFFSET + RLP_MAX_PACKED_LEN {
            usize::from(head - RLP_LIST_OFFSET - RLP_MAX_PACKED_LEN)
        } else {
            return Err(format!("Invalid head byte {:x} for encoded header", head));
        };
        let mut length: usize = 0;
        for i in 0..length_bytes {
            length = (256 * length) + usize::from(reader[i + 1]);
        }

        let payload_offset = 1 + length_bytes;
        let encoded = reader.read_next(payload_offset + length);

        let mut payload_reader = Reader::from(&encoded[payload_offset..]);

        Self::validate_small_fixed_field::<32>(&mut payload_reader)?; // parent_hash
        Self::validate_small_fixed_field::<32>(&mut payload_reader)?; // ommers_hash
        Self::validate_small_fixed_field::<20>(&mut payload_reader)?; // beneficiary
        Self::validate_small_fixed_field::<32>(&mut payload_reader)?; // state_root
        Self::validate_small_fixed_field::<32>(&mut payload_reader)?; // transactions_root
        Self::validate_small_fixed_field::<32>(&mut payload_reader)?; // receipts_root

        Ok(Self {
            encoded,
            payload_offset,
        })
    }

    pub fn parent_hash(&self) -> &[u8; 32] {
        self.encoded[self.payload_offset + 1..][..32]
            .try_into()
            .unwrap()
    }

    pub fn receipts_root(&self) -> &[u8; 32] {
        self.encoded[self.payload_offset + 33 + 33 + 21 + 33 + 33 + 1..][..32]
            .try_into()
            .unwrap()
    }

    fn validate_small_fixed_field<const N: u8>(payload_reader: &mut Reader) -> Result<(), String> {
        let expected_byte = RLP_STR_OFFSET + N;
        let byte = payload_reader[0];
        if byte != expected_byte {
            return Err(format!(
                "Expected string header byte {:x} not {:x}",
                expected_byte, byte
            ));
        }
        payload_reader.read_next((N + 1).into());
        Ok(())
    }
}

impl<'a> Deref for EncodedHeaderLens<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.encoded
    }
}

impl<'a> AsRef<[u8]> for EncodedHeaderLens<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_rlp::Encodable;

    #[test]
    fn simple_header_equivalence() {
        let mut header = Header::default();
        header.parent_hash = B256::repeat_byte(0xf1);
        header.receipts_root = B256::with_last_byte(0xcc);

        let mut encoded = Vec::<u8>::new();
        header.encode(&mut encoded);

        let mut reader = Reader::from(encoded.as_slice());
        assert_eq!(reader.len(), encoded.len());

        let header_lens = EncodedHeaderLens::read_from(&mut reader).unwrap();
        assert_eq!(reader.len(), 0);

        assert_eq!(header_lens.len(), encoded.len());
        assert_eq!(header_lens.hash(), header.hash_slow());
        assert_eq!(header_lens.parent_hash(), header.parent_hash);
        assert_eq!(header_lens.receipts_root(), header.receipts_root);
    }
}
