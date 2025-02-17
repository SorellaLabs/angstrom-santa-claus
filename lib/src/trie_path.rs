use crate::receipt_trie::*;

#[derive(Debug, Clone)]
pub(crate) struct TriePath<'a>(&'a [u8]);

impl<'a> std::ops::Deref for TriePath<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> TriePath<'a> {
    pub(crate) fn new(path: &'a [u8]) -> Self {
        assert!(path.len() >= 1, "Path must be at least 1 byte long");
        let new_path = Self(path);
        assert!(
            new_path.nibbles() <= 64,
            "Path must be at most 64 nibbles long"
        );
        new_path
    }

    pub(crate) fn is_odd(&self) -> bool {
        self.0[0] & ODD_NIBBLES_FLAG != 0
    }

    pub(crate) fn is_leaf(&self) -> bool {
        self.0[0] & PATH_FLAG_MASK == LEAF_PATH_FLAG
    }

    pub(crate) fn is_extension(&self) -> bool {
        self.0[0] & PATH_FLAG_MASK == EXTENSION_PATH_FLAG
    }

    /// Total nibbles in path
    pub(crate) fn nibbles(&self) -> u8 {
        (self.len() as u8 - 1) * 2 + self.is_odd() as u8
    }

    /// Total bytes in path
    pub(crate) fn bytes(&self) -> u8 {
        (self.len() as u8 - 1) + self.is_odd() as u8
    }

    pub(crate) fn write_bytes(&self, buf: &mut Vec<u8>) {
        if self.is_odd() {
            buf.push(self.0[0] & NIBBLE_MASK);
        }
        buf.extend_from_slice(&self[1..]);
    }
}
