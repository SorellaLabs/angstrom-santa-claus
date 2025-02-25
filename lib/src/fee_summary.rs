use crate::bytes_wrapper;
use alloy_primitives::Address;

const FEE_ENTRY_SIZE: usize = 36; // 20 bytes for asset address + 16 for u128 amount
const ASSET_OFFSET: usize = 0;
const AMOUNT_OFFSET: usize = 20;

#[derive(Debug, Clone, Copy)]
pub struct FeeEntry([u8; FEE_ENTRY_SIZE]);

impl FeeEntry {
    pub fn new(addr: Address, amount: u128) -> Self {
        let mut bytes = [0; FEE_ENTRY_SIZE];

        bytes[ASSET_OFFSET..AMOUNT_OFFSET].copy_from_slice(addr.as_slice());
        bytes[AMOUNT_OFFSET..].copy_from_slice(&amount.to_be_bytes());

        Self(bytes)
    }
    pub fn asset(&self) -> &Address {
        self[ASSET_OFFSET..AMOUNT_OFFSET].try_into().unwrap()
    }

    pub fn amount(&self) -> u128 {
        u128::from_be_bytes(self[AMOUNT_OFFSET..].try_into().unwrap())
    }
}

impl std::borrow::Borrow<[u8]> for FeeEntry {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

impl std::ops::Deref for FeeEntry {
    type Target = [u8; FEE_ENTRY_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8; FEE_ENTRY_SIZE]> for FeeEntry {
    fn as_ref(&self) -> &[u8; FEE_ENTRY_SIZE] {
        self
    }
}

impl AsRef<[u8]> for FeeEntry {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a FeeEntry {
    type Error = <&'a [u8; FEE_ENTRY_SIZE] as TryFrom<&'a [u8]>>::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        <&[u8; FEE_ENTRY_SIZE]>::try_from(value).map(|r| unsafe { core::mem::transmute(r) })
    }
}

bytes_wrapper!(FeeSummaryInspector);

#[derive(Debug, Clone)]
pub enum FeeSummaryInspectorError {
    DoesNotHoldEvenEntries { length: usize },
}

impl<'a> TryFrom<&'a [u8]> for FeeSummaryInspector<'a> {
    type Error = FeeSummaryInspectorError;

    fn try_from(entry_bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if entry_bytes.len() % FEE_ENTRY_SIZE != 0 {
            return Err(FeeSummaryInspectorError::DoesNotHoldEvenEntries {
                length: entry_bytes.len(),
            });
        }
        Ok(Self(entry_bytes))
    }
}

impl<'a> std::ops::Index<usize> for FeeSummaryInspector<'a> {
    type Output = FeeEntry;

    fn index(&self, index: usize) -> &Self::Output {
        self.as_ref()[index * FEE_ENTRY_SIZE..][..FEE_ENTRY_SIZE]
            .try_into()
            .unwrap()
    }
}
