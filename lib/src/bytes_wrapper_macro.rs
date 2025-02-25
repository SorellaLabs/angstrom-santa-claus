#[macro_export]
macro_rules! bytes_wrapper {
    ($ident:ident) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $ident<'a>(&'a [u8]);

        impl std::ops::Deref for $ident<'_> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<[u8]> for $ident<'_> {
            fn as_ref(&self) -> &[u8] {
                self
            }
        }
    };
}

#[macro_export]
macro_rules! fixed_bytes_wrapper {
    ($ident:ident, $size:expr) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $ident<'a>(&'a [u8; $size]);

        impl std::ops::Deref for $ident<'_> {
            type Target = [u8; $size];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<[u8; $size]> for $ident<'_> {
            fn as_ref(&self) -> &[u8; $size] {
                self
            }
        }

        impl AsRef<[u8]> for $ident<'_> {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl<'a> TryFrom<&'a [u8]> for $ident<'a> {
            type Error = <&'a [u8; $size] as TryFrom<&'a [u8]>>::Error;

            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                <&[u8; $size]>::try_from(value).map(Self)
            }
        }
    };
}
