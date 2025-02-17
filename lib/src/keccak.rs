use std::ops::{Deref, DerefMut};
use tiny_keccak::keccakf;

type Word = u32;

const STATE_BYTES: usize = 200;
const WORD_BYTES: usize = (Word::BITS as usize) / 8;
const WORDS: usize = STATE_BYTES / WORD_BYTES;

const DELIM: u8 = 0x01;

const BLOCK_SIZE: usize = 136;

#[derive(Debug, Clone)]
struct Keccak256State([Word; WORDS]);

impl Deref for Keccak256State {
    type Target = [Word; WORDS];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Keccak256State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Default for Keccak256State {
    fn default() -> Self {
        Self([0; WORDS])
    }
}

impl AsMut<[u8; STATE_BYTES]> for Keccak256State {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; STATE_BYTES] {
        unsafe { core::mem::transmute(self) }
    }
}

#[derive(Debug, Clone)]
pub struct Keccak256 {
    state: Keccak256State,
    offset: usize,
    first_block: bool,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self {
            state: Default::default(),
            offset: 0,
            first_block: true,
        }
    }
}

/// Keccak256 struct optimized for repeated hashing & outputting 32-byte hashes.
impl Keccak256 {
    #[inline]
    fn permute(&mut self) {
        keccakf(unsafe { core::mem::transmute(&mut self.state) })
    }

    #[inline]
    fn absorb<T: std::ops::BitXorAssign<T> + Copy>(first: bool, dst: &mut T, src: &T) {
        if first {
            *dst = *src;
        } else {
            *dst ^= *src;
        }
    }

    /// Safety: Assumes caller has checked that `block` is aligned with width of ```Word```
    #[inline]
    unsafe fn absorb_aligned(&mut self, first: bool, block: &[u8]) {
        let block: &[Word] =
            std::slice::from_raw_parts(block.as_ptr() as *const Word, BLOCK_SIZE / WORD_BYTES);

        for i in 0..BLOCK_SIZE / WORD_BYTES {
            Self::absorb(first, &mut self.state[i], &block[i]);
        }

        self.permute();
    }
    #[inline]
    fn absorb_block(&mut self, first: bool, block: &[u8]) {
        for (s, b) in self.state.iter_mut().zip(block.chunks_exact(WORD_BYTES)) {
            Self::absorb(first, s, &Word::from_le_bytes(b.try_into().unwrap()));
        }

        self.permute();
    }

    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        let mut input = input.as_ref();
        let offset = self.offset;
        let rem = BLOCK_SIZE - self.offset;

        // If input not long enough to fill block partially absorb.
        if input.len() < rem {
            let state_bytes = self.state.as_mut();
            for (s, inp) in state_bytes.iter_mut().zip(input) {
                Self::absorb(self.first_block, s, inp);
            }
            self.offset = offset + input.len();
            return;
        }

        // If last block was incomplete, complete first.
        if offset != 0 {
            let (left, right) = input.split_at(rem);
            input = right;

            let state_bytes = self.state.as_mut();
            for (s, inp) in state_bytes[offset..].iter_mut().zip(left) {
                Self::absorb(self.first_block, s, inp);
            }

            self.permute();
            self.first_block = false;
        }

        let align_offset = input.as_ptr().align_offset(WORD_BYTES);

        if self.first_block && input.len() >= BLOCK_SIZE {
            let (block, right) = input.split_at(BLOCK_SIZE);
            input = right;

            if align_offset == 0 {
                unsafe { self.absorb_aligned(true, block) };
            } else {
                self.absorb_block(true, block);
            }

            self.first_block = false;
        }

        // Absorb remaining full blocks.
        if align_offset == 0 {
            while input.len() >= BLOCK_SIZE {
                let (block, right) = input.split_at(BLOCK_SIZE);
                input = right;

                // If `input` was aligned initially and we only split in aligned increments we know
                // the resulting slice is aligned.
                unsafe { self.absorb_aligned(false, block) };
            }
        } else {
            while input.len() >= BLOCK_SIZE {
                let (block, right) = input.split_at(BLOCK_SIZE);
                input = right;

                self.absorb_block(false, block);
            }
        }

        let state_bytes = self.state.as_mut();
        for i in 0..input.len() {
            state_bytes[i] ^= input[i];
        }
        self.offset = input.len();
    }

    fn pad(&mut self) {
        let state_bytes = self.state.as_mut();
        if self.first_block {
            for i in self.offset..BLOCK_SIZE {
                state_bytes[i] = 0;
            }
        }

        state_bytes[self.offset] ^= DELIM;
        state_bytes[BLOCK_SIZE - 1] ^= 0x80;
    }

    pub fn finalize_and_reset(&mut self, output: &mut [u8; 32]) {
        self.pad();

        self.permute();

        let words_out: &mut [Word; 32 / WORD_BYTES] = unsafe { core::mem::transmute(output) };
        for (a, b) in words_out.iter_mut().zip(*self.state) {
            *a = b;
        }

        self.reset();
    }

    fn reset(&mut self) {
        for i in BLOCK_SIZE / WORD_BYTES..WORDS {
            self.state[i] = 0;
        }
        self.first_block = true;
        self.offset = 0;
    }

    pub fn complete(&mut self, input: &[u8], output: &mut [u8; 32]) {
        self.update(input);
        self.finalize_and_reset(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn test_simple_comparisons() {
        let mut keccak = Keccak256::default();
        let mut hash = [0u8; 32];

        let preimage = "hello";
        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "hello");

        hash = Default::default();
        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "hello (after reset)");

        let preimage = "very long text, incredible, very nice. Multiple bytes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(320);

        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "long string");

        keccak.finalize_and_reset(&mut hash);
        assert_eq!(&hash, keccak256(""), "empty");

        let preimage = "potato";

        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "potato");
    }
}
