//! A cursor over a byte slice that never panics: the part of
//! `sootmark-common`'s `bytes::Reader` (MIT OR Apache-2.0, by the same
//! author as this crate's upstream) that the decoders use.

/// The bytes asked for are not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Eof;

/// A cursor over a byte slice.
#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Move to `position`, which may be the end but not past it.
    pub(crate) fn seek(&mut self, position: usize) -> Result<(), Eof> {
        if position > self.data.len() {
            return Err(Eof);
        }
        self.pos = position;
        Ok(())
    }

    /// Advance by `n` bytes.
    pub(crate) fn skip(&mut self, n: usize) -> Result<(), Eof> {
        self.bytes(n).map(|_| ())
    }

    /// The next `n` bytes.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Eof> {
        let end = self.pos.checked_add(n).ok_or(Eof)?;
        let out = self.data.get(self.pos..end).ok_or(Eof)?;
        self.pos = end;
        Ok(out)
    }

    /// The next `N` bytes as an array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Eof> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Eof> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16_le(&mut self) -> Result<u16, Eof> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn i16_le(&mut self) -> Result<i16, Eof> {
        Ok(i16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32_le(&mut self) -> Result<u32, Eof> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64_le(&mut self) -> Result<u64, Eof> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn i64_le(&mut self) -> Result<i64, Eof> {
        Ok(i64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_stops_at_the_end() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 0, 9]);
        assert_eq!(r.u16_le(), Ok(1));
        assert_eq!(r.u32_le(), Ok(2));
        assert_eq!(r.u16_le(), Err(Eof));
        assert_eq!(r.skip(usize::MAX), Err(Eof));
        assert_eq!(r.u8(), Ok(9), "a failed read does not move");
        assert_eq!(r.u8(), Err(Eof));
        assert_eq!(r.seek(7), Ok(()));
        assert_eq!(r.seek(8), Err(Eof));
        r.seek(0).unwrap();
        assert_eq!(r.i16_le(), Ok(1));
        assert_eq!(r.bytes(2), Ok(&[2, 0][..]));
    }
}
