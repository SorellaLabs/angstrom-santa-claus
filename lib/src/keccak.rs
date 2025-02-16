use tiny_keccak::keccakf;

const WORDS: usize = 25;
const BYTES: usize = WORDS * 8;

#[derive(Debug, Clone)]
pub struct Keccak256 {
    buffer: [u64; WORDS],
    offset: usize,
    first_block: bool,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self {
            buffer: [0u64; WORDS],
            offset: 0,
            first_block: true,
        }
    }
}

const DELIM: u8 = 0x01;
const RATE: usize = 136;

/// Keccak256 struct optimized for repeated hashing & outputting 32-byte hashes.
impl Keccak256 {
    #[inline]
    fn keccak(&mut self) {
        keccakf(&mut self.buffer)
    }

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; BYTES] = unsafe { core::mem::transmute(&mut self.buffer) };
        f(unsafe { buffer.get_unchecked_mut(offset..).get_unchecked_mut(..len) });
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        let buffer: &mut [u8; BYTES] = unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    fn setin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr = *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    pub fn update(&mut self, mut input: &[u8]) {
        let mut rate = RATE - self.offset;
        let mut offset = self.offset;

        if self.first_block {
            if input.len() >= rate {
                self.setin(input, offset, rate);
                self.keccak();
                self.first_block = false;
                input = &input[rate..];
                rate = RATE;
                offset = 0;
            } else {
                self.setin(input, offset, input.len());
                self.offset = offset + input.len();
                return;
            }
        }

        while input.len() >= rate {
            self.xorin(input, offset, rate);
            self.keccak();
            input = &input[rate..];
            rate = RATE;
            offset = 0;
        }

        self.xorin(input, offset, input.len());
        self.offset = offset + input.len();
    }

    fn pad(&mut self) {
        self.execute(self.offset, 1, |buff| buff[0] ^= DELIM);
        self.execute(RATE - 1, 1, |buff| buff[0] ^= 0x80);
    }

    pub fn finalize_and_reset(&mut self, output: &mut [u8; 32]) {
        if self.first_block {
            self.execute(self.offset, RATE - self.offset, |b| {
                for i in 0..b.len() {
                    b[i] = 0;
                }
            });
        }

        self.pad();

        self.keccak();

        let words_out: &mut [u64; 4] = unsafe { core::mem::transmute(output) };
        for i in 0..4 {
            words_out[i] = self.buffer[i];
        }

        self.reset();
    }

    fn reset(&mut self) {
        for i in RATE / 8..WORDS {
            self.buffer[i] = 0;
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

        assert_eq!(&hash, keccak256(preimage), "first");

        hash = Default::default();
        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "after reset");

        let preimage = "very long text, incredible, very nice. Multiple bytes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(320);

        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "long");

        keccak.finalize_and_reset(&mut hash);
        assert_eq!(&hash, keccak256(""), "empty");

        let preimage = "potato";

        keccak.update(preimage.as_bytes());
        keccak.finalize_and_reset(&mut hash);

        assert_eq!(&hash, keccak256(preimage), "potato");
    }
}
