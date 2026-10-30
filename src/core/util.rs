//! Small formatting helpers shared by the UI. No external date or locale dependencies: the app
//! only ever needs UTC clock times and short relative ages.

use std::time::{SystemTime, UNIX_EPOCH};

/// `14:32:07` in UTC, for log and journal timestamps.
pub fn utc_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    hms_from_epoch(secs)
}

pub fn hms_from_epoch(secs: u64) -> String {
    let day = secs % 86_400;
    format!("{:02}:{:02}:{:02}", day / 3600, (day % 3600) / 60, day % 60)
}

/// `just now`, `12s ago`, `4m ago`, `2h ago`.
pub fn ago(seconds: u64) -> String {
    match seconds {
        0 => "just now".to_string(),
        1..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/// `999`, `1.2k`, `13k` — compact enough for a table column.
pub fn count(value: u64) -> String {
    match value {
        0..=999 => value.to_string(),
        1000..=9999 => format!("{:.1}k", value as f64 / 1000.0),
        _ => format!("{:.0}k", value as f64 / 1000.0),
    }
}

/// Shortens `text` to at most `width` characters, adding an ellipsis when it had to cut.
pub fn ellipsize(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let len = text.chars().count();
    if len <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_read_naturally() {
        assert_eq!(ago(0), "just now");
        assert_eq!(ago(1), "1s ago");
        assert_eq!(ago(90), "1m ago");
        assert_eq!(ago(7300), "2h ago");
        assert_eq!(ago(90_000), "1d ago");
    }

    #[test]
    fn counts_are_compact() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1234), "1.2k");
        assert_eq!(count(13_400), "13k");
    }

    #[test]
    fn epoch_converts_to_utc_clock() {
        // 1970-01-02 03:04:05 UTC
        assert_eq!(hms_from_epoch(86_400 + 3 * 3600 + 4 * 60 + 5), "03:04:05");
    }

    #[test]
    fn ellipsize_keeps_short_text_intact() {
        assert_eq!(ellipsize("abc", 5), "abc");
        assert_eq!(ellipsize("abcdef", 4), "abc…");
        assert_eq!(ellipsize("abc", 0), "");
    }
}
