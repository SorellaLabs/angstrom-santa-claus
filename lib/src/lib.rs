use alloy_primitives::B256;

mod partial_header;
pub mod reader;
pub mod receipt_trie;
pub use partial_header::PartialHeader;
pub use reader::Reader;

pub fn verify_hash_chain<I, H, T>(mut last_hash: B256, headers: I) -> Option<B256>
where
    T: AsRef<[u8]>,
    H: AsRef<PartialHeader<T>>,
    I: IntoIterator<Item = H>,
{
    let mut headers = headers.into_iter();
    while let Some(header) = headers.next() {
        let header = header.as_ref();
        if header.parent_hash != last_hash {
            return None;
        }
        last_hash = header.hash();
    }
    Some(last_hash)
}
