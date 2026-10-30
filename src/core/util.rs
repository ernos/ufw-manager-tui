//! Small formatting helpers shared by the UI. No external date or locale dependencies: the app
//! only ever needs UTC clock times and short relative ages.

use std::time::{SystemTime, UNIX_EPOCH};

/**
 * Returns the current UTC time of day.
 *
 * The result is used for log and journal timestamps. If the system clock is
 * before the Unix epoch, the time falls back to `00:00:00`.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * A `String` in `HH:MM:SS` form, for example `14:32:07`.
 */
pub fn utc_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    hms_from_epoch(secs)
}

/**
 * Formats a Unix epoch timestamp as a UTC wall-clock time.
 *
 * Only the time of day is rendered; the date part of the timestamp is
 * discarded, so the result repeats every 24 hours.
 *
 * # Arguments
 *
 * * `secs` (`u64`) - Seconds since the Unix epoch.
 *
 * # Returns
 *
 * A `String` in `HH:MM:SS` form, zero-padded, for the UTC time of day.
 */
pub fn hms_from_epoch(secs: u64) -> String {
    let day = secs % 86_400;
    format!("{:02}:{:02}:{:02}", day / 3600, (day % 3600) / 60, day % 60)
}

/**
 * Renders an age in seconds as a short relative phrase.
 *
 * The unit grows with the magnitude: seconds, minutes, hours, then days.
 *
 * # Arguments
 *
 * * `seconds` (`u64`) - The age to render, in seconds.
 *
 * # Returns
 *
 * A `String` such as `just now`, `12s ago`, `4m ago`, `2h ago` or `3d ago`.
 */
pub fn ago(seconds: u64) -> String {
    match seconds {
        0 => "just now".to_string(),
        1..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86_399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/**
 * Renders a count compactly enough for a table column.
 *
 * Values below 1000 are shown in full, values below 10000 keep one decimal,
 * and larger values are rounded to whole thousands.
 *
 * # Arguments
 *
 * * `value` (`u64`) - The count to render.
 *
 * # Returns
 *
 * A `String` such as `999`, `1.2k` or `13k`.
 */
pub fn count(value: u64) -> String {
    match value {
        0..=999 => value.to_string(),
        1000..=9999 => format!("{:.1}k", value as f64 / 1000.0),
        _ => format!("{:.0}k", value as f64 / 1000.0),
    }
}

/**
 * Shortens text to at most `width` characters.
 *
 * When the text has to be cut, the last character is replaced by an ellipsis.
 * Widths are measured in characters, not bytes, so multi-byte text is handled
 * correctly.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The text to shorten.
 * * `width` (`usize`) - The maximum number of characters to keep.
 *
 * # Returns
 *
 * A `String` containing the original text when it fits, an empty string when
 * `width` is `0`, or the truncated text ending in `…`.
 */
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
    /**
     * Verifies that relative ages are rendered with the expected unit.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn ages_read_naturally() {
        assert_eq!(ago(0), "just now");
        assert_eq!(ago(1), "1s ago");
        assert_eq!(ago(90), "1m ago");
        assert_eq!(ago(7300), "2h ago");
        assert_eq!(ago(90_000), "1d ago");
    }

    #[test]
    /**
     * Verifies that large counts are abbreviated with a `k` suffix.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn counts_are_compact() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1234), "1.2k");
        assert_eq!(count(13_400), "13k");
    }

    #[test]
    /**
     * Verifies that an epoch value converts to the correct UTC clock time.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn epoch_converts_to_utc_clock() {
        // 1970-01-02 03:04:05 UTC
        assert_eq!(hms_from_epoch(86_400 + 3 * 3600 + 4 * 60 + 5), "03:04:05");
    }

    #[test]
    /**
     * Verifies that short text is returned unchanged and long text is cut.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn ellipsize_keeps_short_text_intact() {
        assert_eq!(ellipsize("abc", 5), "abc");
        assert_eq!(ellipsize("abcdef", 4), "abc…");
        assert_eq!(ellipsize("abc", 0), "");
    }
}
