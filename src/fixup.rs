//! Update sequence arrays: how NTFS detects a page only partly written.
//!
//! Before a multi-sector structure is written, the last two bytes of each
//! 512-byte stride are saved in the structure's update sequence array and
//! replaced by the update sequence number, which changes on every write.
//! Reading it back, every stride must end with that number; the saved
//! bytes are then put back. A stride that doesn't is a torn write.

use core::fmt;

/// Strides are one sector.
const STRIDE: usize = 512;
/// Where the array's offset and count are, in every protected structure.
const ARRAY_OFFSET_AT: usize = 4;
const ARRAY_COUNT_AT: usize = 6;
/// Signature, offset and count come before the array.
const MIN_ARRAY_OFFSET: usize = 8;

/// Why a structure's update sequence array couldn't be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fixup {
    /// The array doesn't fit the structure: damage.
    Malformed,
    /// This stride (counting from 0) doesn't end with the update sequence
    /// number: a torn write.
    Torn(usize),
}

impl fmt::Display for Fixup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("its update sequence array doesn't fit it"),
            Self::Torn(stride) => write!(
                f,
                "sector {stride} doesn't end with its update sequence number (a torn write)"
            ),
        }
    }
}

/// Check and remove the protection of `block`, a whole structure (a
/// multiple of 512 bytes). Returns where the array ends.
pub(crate) fn unprotect(block: &mut [u8]) -> Result<usize, Fixup> {
    let field = |at: usize| {
        block
            .get(at..at + 2)
            .map(|bytes| usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
    };
    let (Some(offset), Some(count)) = (field(ARRAY_OFFSET_AT), field(ARRAY_COUNT_AT)) else {
        return Err(Fixup::Malformed);
    };
    let strides = block.len() / STRIDE;
    let end = offset + 2 * count;
    // The array is one number and one saved pair per stride, and lies in
    // the first stride, before its protected bytes.
    if !block.len().is_multiple_of(STRIDE)
        || strides == 0
        || count != strides + 1
        || offset < MIN_ARRAY_OFFSET
        || end > STRIDE - 2
    {
        return Err(Fixup::Malformed);
    }
    let (number, saved) = (
        [block[offset], block[offset + 1]],
        block[offset + 2..end].to_vec(),
    );
    for (stride, original) in saved.as_chunks::<2>().0.iter().enumerate() {
        let last = (stride + 1) * STRIDE - 2;
        if block[last..last + 2] != number {
            return Err(Fixup::Torn(stride));
        }
        block[last..last + 2].copy_from_slice(original);
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two sectors, protected with update sequence number 7.
    fn protected() -> Vec<u8> {
        let mut block = vec![0xAA; 1024];
        block[4..8].copy_from_slice(&[40, 0, 3, 0]);
        block[40..46].copy_from_slice(&[7, 0, 0x11, 0x22, 0x33, 0x44]);
        block[510..512].copy_from_slice(&[7, 0]);
        block[1022..1024].copy_from_slice(&[7, 0]);
        block
    }

    #[test]
    fn restores_the_saved_bytes() {
        let mut block = protected();
        assert_eq!(unprotect(&mut block), Ok(46));
        assert_eq!(block[510..512], [0x11, 0x22]);
        assert_eq!(block[1022..1024], [0x33, 0x44]);
    }

    #[test]
    fn a_torn_sector() {
        let mut block = protected();
        block[1022] = 8;
        assert_eq!(unprotect(&mut block), Err(Fixup::Torn(1)));
    }

    #[test]
    fn arrays_that_do_not_fit() {
        for (at, value) in [(6, 2), (6, 4), (4, 4), (5, 0x02), (5, 0xFF)] {
            let mut block = protected();
            block[at] = value;
            assert_eq!(unprotect(&mut block), Err(Fixup::Malformed), "{at}");
        }
        assert_eq!(unprotect(&mut [0; 7]), Err(Fixup::Malformed));
        assert_eq!(unprotect(&mut protected()[..1000]), Err(Fixup::Malformed));
    }
}
