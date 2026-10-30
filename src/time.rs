//! Times: Windows FILETIMEs (100 ns intervals since 1601-01-01 UTC).
//! Replaces `sootmark-common`'s general `Ts` (MIT OR Apache-2.0, by the
//! same author as this crate's upstream) with the raw value and the
//! formatting it gave, as ys-usn-journal-parser does.

use core::fmt;

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
/// FILETIME ticks between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;

/// A FILETIME as recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Filetime(u64);

impl Filetime {
    /// The FILETIME `value`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The value as recorded.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// 100 ns ticks since 1970-01-01 UTC, when the value is a time: `None`
    /// for 0 (never set), the `0x7FFF_FFFF_FFFF_FFFF` / `u64::MAX` sentinels
    /// and values above `i64::MAX`.
    #[must_use]
    pub fn unix_ticks(self) -> Option<i64> {
        match self.0 {
            0 | 0x7FFF_FFFF_FFFF_FFFF | u64::MAX => None,
            v => i64::try_from(v).ok().map(|v| v - FILETIME_UNIX_OFFSET),
        }
    }

    /// Whether it is a time in a year from `min_year` to `max_year`.
    #[must_use]
    pub fn year_within(self, min_year: i64, max_year: i64) -> bool {
        self.unix_ticks().is_some_and(|ticks| {
            let (year, _, _) = civil_from_days(ticks.div_euclid(TICKS_PER_DAY));
            (min_year..=max_year).contains(&year)
        })
    }

    /// `YYYY-MM-DDTHH:MM:SS.fffffffZ` with the full 100 ns precision; years
    /// outside 0000–9999 use the expanded `±YYYYYY` form. `None` when
    /// [`Filetime::unix_ticks`] is.
    #[must_use]
    pub fn to_iso8601(self) -> Option<String> {
        let ticks = self.unix_ticks()?;
        let days = ticks.div_euclid(TICKS_PER_DAY);
        let rem = ticks.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let secs = rem / TICKS_PER_SECOND;
        let frac = rem % TICKS_PER_SECOND;
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+07}")
        };
        Some(format!(
            "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{frac:07}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60,
        ))
    }
}

impl fmt::Display for Filetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_iso8601() {
            Some(s) => f.write_str(&s),
            None if self.0 == 0 => f.write_str("<not set>"),
            None => write!(f, "<invalid 0x{:016x}>", self.0),
        }
    }
}

/// Proleptic Gregorian `(year, month, day)` for days since 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes_keep_100_ns() {
        let t = Filetime::new(125_911_584_000_000_000);
        assert_eq!(
            t.to_iso8601().as_deref(),
            Some("2000-01-01T00:00:00.0000000Z")
        );
        assert_eq!(
            Filetime::new(133_515_874_611_440_142).to_string(),
            "2024-02-05T06:17:41.1440142Z"
        );
        assert_eq!(
            Filetime::new(1).to_iso8601().as_deref(),
            Some("1601-01-01T00:00:00.0000001Z")
        );
        assert_eq!(Filetime::new(0).to_iso8601(), None);
        assert_eq!(Filetime::new(0).to_string(), "<not set>");
        assert_eq!(Filetime::new(u64::MAX).unix_ticks(), None);
        assert_eq!(
            Filetime::new(1 << 63).to_string(),
            "<invalid 0x8000000000000000>"
        );
        assert_eq!(
            Filetime::new(0x7FFF_FFFF_FFFF_FFFE).to_iso8601().as_deref(),
            Some("+030828-09-14T02:48:05.4775806Z")
        );
    }

    #[test]
    fn years() {
        let t = Filetime::new(125_911_584_000_000_000);
        assert!(t.year_within(2000, 2000));
        assert!(!t.year_within(2001, 2200));
        assert!(!Filetime::new(0).year_within(1601, 9999));
    }
}
