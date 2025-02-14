#[derive(Debug, Clone)]
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn read_byte(&mut self) -> u8 {
        let b = self.0[0];
        self.0 = &self.0[1..];
        b
    }

    pub fn read_next(&mut self, size: usize) -> &'a [u8] {
        let slice = &self.0[..size];
        self.0 = &self.0[size..];
        slice
    }
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

impl<'a> std::ops::Deref for Reader<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> AsRef<[u8]> for Reader<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}
