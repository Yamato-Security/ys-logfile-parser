//! UTF-16 names that never lose information: `sootmark-common`'s
//! `text::utf16le` and `text::utf16le_until_nul` (MIT OR Apache-2.0).
//!
//! An unpaired surrogate (attacker-crafted names have them) is escaped as
//! `\u{XXXX}` and an odd trailing byte as `\x{XX}` instead of being replaced
//! with U+FFFD, which would make two different names look identical.

use core::fmt::Write;

/// Decoded text plus whether the input needed escaping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub(crate) text: String,
    pub(crate) escaped: bool,
}

/// Decode UTF-16LE bytes in full (NULs included).
pub(crate) fn utf16le(bytes: &[u8]) -> Decoded {
    decode(bytes, false)
}

/// Decode UTF-16LE bytes up to the first NUL unit.
pub(crate) fn utf16le_until_nul(bytes: &[u8]) -> Decoded {
    decode(bytes, true)
}

fn decode(bytes: &[u8], stop_at_nul: bool) -> Decoded {
    let (units, trailing_byte) = split_units(bytes, stop_at_nul);
    let mut text = String::with_capacity(units.len() / 2);
    let mut escaped = false;
    for item in char::decode_utf16(
        units
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]])),
    ) {
        match item {
            Ok(c) => text.push(c),
            Err(e) => {
                escaped = true;
                let _ = write!(text, "\\u{{{:04x}}}", e.unpaired_surrogate());
            }
        }
    }
    if let Some(byte) = trailing_byte {
        escaped = true;
        let _ = write!(text, "\\x{{{byte:02x}}}");
    }
    Decoded { text, escaped }
}

/// The whole code units to decode, and a dangling odd byte if decoding runs
/// to the end of the input.
fn split_units(bytes: &[u8], stop_at_nul: bool) -> (&[u8], Option<u8>) {
    let whole_units = bytes.len() & !1;
    if stop_at_nul
        && let Some(nul) = bytes[..whole_units]
            .as_chunks::<2>()
            .0
            .iter()
            .position(|c| c == &[0, 0])
    {
        return (&bytes[..nul * 2], None);
    }
    (&bytes[..whole_units], bytes.get(whole_units).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn invalid_units_are_escaped_not_replaced() {
        assert_eq!(utf16le(&le(&[0x61, 0x3042])).text, "aあ");
        let lone = utf16le(&le(&[0x61, 0xD800, 0x62]));
        assert_eq!(lone.text, "a\\u{d800}b");
        assert!(lone.escaped);
        let odd = utf16le(&[0x61, 0x00, 0x7F]);
        assert_eq!(odd.text, "a\\x{7f}");
        assert!(odd.escaped);
        assert!(
            !utf16le(&le(&[0xD83D, 0xDE00])).escaped,
            "a surrogate pair is a character"
        );
    }

    #[test]
    fn until_nul() {
        assert_eq!(utf16le_until_nul(&le(&[0x24, 0x4A, 0, 0x41])).text, "$J");
        assert_eq!(utf16le(&le(&[0x24, 0, 0x41])).text, "$\0A");
        let odd = utf16le_until_nul(&[0x61, 0x00, 0x62]);
        assert_eq!(odd.text, "a\\x{62}");
    }
}
