use crate::rlp::*;
use alloy_primitives::{Address, B256};
use typenum::{IsLess, True, Unsigned, U20, U32, U56};

type HeaderValidationError = String;

fn validate_small_fixed_field<N: Unsigned + IsLess<U56, Output = True>>(
    payload: &mut &[u8],
) -> Result<(), HeaderValidationError> {
    if payload.len() < N::USIZE + 1 {
        return Err(format!(
            "Remaining payload too short to be encoding RLP string of length {}",
            N::USIZE
        ));
    }
    let byte = payload[0];
    let expected_byte = RLP_STR_OFFSET + N::U8;
    if byte != expected_byte {
        return Err(format!(
            "Expected string header byte {:x} not {:x}",
            expected_byte, byte
        ));
    }
    *payload = &payload[N::USIZE + 1..];
    Ok(())
}

pub trait RLPListInspector: std::ops::Deref<Target = [u8]> {
    fn payload_offset(&self) -> usize;

    fn encoded(&self) -> &[u8];
}

pub trait ParentHashInspector: RLPListInspector {
    fn validate_field(payload: &mut &[u8]) -> Result<(), HeaderValidationError> {
        validate_small_fixed_field::<U32>(payload)
    }

    fn parent_hash(&self) -> &B256 {
        self[self.payload_offset() + 1..][..32].try_into().unwrap()
    }
}

macro_rules! fixed_field_inspector {
    (
        $trait_name:ident :
        $parent_trait:ident,
        $field_name:ident,
        $field_type:ty,
        $field_size:ty,
        $offset:expr
    ) => {
        pub trait $trait_name: $parent_trait {
            fn validate_field(payload: &mut &[u8]) -> Result<(), HeaderValidationError> {
                // If parent is not RLPListInspector, call its validation
                <Self as $parent_trait>::validate_field(payload)?;
                validate_small_fixed_field::<$field_size>(payload)
            }

            fn $field_name(&self) -> &$field_type {
                self[self.payload_offset() + $offset + 1..][..::std::mem::size_of::<$field_type>()]
                    .try_into()
                    .unwrap()
            }
        }

        impl<I: $parent_trait> $trait_name for I {}
    };
}

fixed_field_inspector!(
    OmmersHashInspector: ParentHashInspector,
    ommers_hash,
    B256,
    U32,
    33
);

fixed_field_inspector!(
    BeneficiaryInspector: OmmersHashInspector,
    beneficiary,
    Address,
    U20,
    33 + 33
);

fixed_field_inspector!(
    StateRootInspector: BeneficiaryInspector,
    state_root,
    B256,
    U32,
    33 + 33 + 21
);

fixed_field_inspector!(
    TransactionRootInspector: StateRootInspector,
    transaction_root,
    B256,
    U32,
    33 + 33 + 21 + 33
);

fixed_field_inspector!(
    ReceiptsRootInspector: TransactionRootInspector,
    receipts_root,
    B256,
    U32,
    33 + 33 + 21 + 33 + 33
);
