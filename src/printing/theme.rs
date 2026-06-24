//! Centralized terminal presentation layer.
//!
//! Every subcommand renders its human-readable output through these helpers so
//! the visual language ("badges + rules") stays consistent. Color is applied via
//! the `colored` crate, which auto-disables on a non-TTY / when `NO_COLOR` is set,
//! so piped output degrades to plain text. Each status badge always carries a
//! short text label next to its glyph (e.g. `▲ CRIT` vs `▲ HIGH`, `● PASS`), so
//! statuses stay distinguishable by glyph + label even without color.
//!
//! These helpers only decorate *framing* (section titles, labels, badges,
//! spinners). They never wrap the actual data lines (tokens, JSON, PEM), so
//! `--json` output and piped data streams remain byte-faithful.

use colored::{Color, Colorize};
use indicatif::{ProgressBar, ProgressStyle};
use std::fmt::Display;
use std::time::Duration;

/// Two-space indent used for all body lines under a section.
pub const INDENT: &str = "  ";
/// Left accent glyph that prefixes every section/sub-section title.
const ACCENT_BAR: &str = "▎";
/// Glyph used to draw the horizontal rule after a top-level section title.
const RULE_CHAR: &str = "─";
/// Target column width a top-level section header (bar + title + rule) fills to.
const SECTION_WIDTH: usize = 46;

/// Braille spinner frames shared by every spinner and progress bar.
pub const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// Status glyphs — kept in one place so the logger, the inline `log_*` helpers and
// the badge renderer all speak the same visual language.
pub const G_OK: &str = "✓";
pub const G_INFO: &str = "▸";
pub const G_WARN: &str = "⚠";
pub const G_ERR: &str = "✗";
pub const G_DEBUG: &str = "●";
pub const G_TRACE: &str = "○";

/// Build a top-level section header: accent bar + UPPERCASED bold title + dim rule.
///
/// e.g. `▎ DECODE ─────────────────────────────────`
pub fn section_line(title: &str) -> String {
    let title_up = title.to_uppercase();
    // Visible columns consumed by "▎ " + title + " " before the rule begins.
    let prefix_cols = 2 + title_up.chars().count() + 1;
    let dashes = SECTION_WIDTH.saturating_sub(prefix_cols).max(3);
    format!(
        "{} {} {}",
        ACCENT_BAR.cyan(),
        title_up.bold(),
        RULE_CHAR.repeat(dashes).dimmed()
    )
}

/// Build a sub-section header: accent bar + bold title (no rule).
///
/// e.g. `▎ Header`
pub fn subsection_line(title: &str) -> String {
    format!("{} {}", ACCENT_BAR.cyan(), title.bold())
}

/// Build a key/value row: dim, left-padded label followed by the value.
///
/// The label is padded *before* coloring so alignment is correct even when ANSI
/// escape sequences are present (padding a `ColoredString` would count the escape
/// bytes and silently break the columns under a real TTY).
pub fn kv_line(label: &str, value: impl Display, width: usize) -> String {
    let padded = format!("{label:<width$}");
    format!("{}{}{}", INDENT, padded.dimmed(), value)
}

/// Default-width key/value row (14 columns), matching the historical layout.
pub fn kv(label: &str, value: impl Display) -> String {
    kv_line(label, value, 14)
}

/// Build a status badge padded to 4 columns: `<glyph> LABEL` rendered in `color`.
///
/// 4 columns keeps the scan severity badges aligned (`PASS`, `CRIT`, `HIGH`,
/// `MED `, `LOW `). Callers with wider labels should use [`badge_width`].
pub fn badge(glyph: &str, label: &str, color: Color) -> String {
    badge_width(glyph, label, color, 4)
}

/// Build a status badge padded to `width` columns: `<glyph> LABEL` in `color`.
///
/// The label is padded *before* coloring (same ANSI-safety reason as [`kv_line`]).
/// Labels longer than `width` are never truncated — pass a `width` that fits the
/// widest label in a column so e.g. `VALID`/`INVALID` rows line up.
pub fn badge_width(glyph: &str, label: &str, color: Color, width: usize) -> String {
    let padded = format!("{label:<width$}");
    format!("{} {}", glyph.color(color), padded.color(color).bold())
}

/// Build an inline status line: `<glyph> message` with only the glyph colored.
pub fn status_line(glyph: &str, color: Color, message: impl Display) -> String {
    format!("{} {}", glyph.color(color), message)
}

/// Create an indeterminate braille spinner with the shared style.
pub fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("valid spinner template")
            .tick_strings(BRAILLE),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a determinate progress bar with the shared "badges + rules" style.
///
/// `prefix` is shown bold before the bar (e.g. `Cracking`); callers set the
/// message via `set_message` for a trailing detail such as the current rate.
pub fn progress_bar(total: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.cyan} {prefix:.bold} [{bar:28.cyan/dim}] {percent:>3}%  {pos}/{len}  {msg}  {elapsed:>5}",
            )
            .expect("valid progress bar template")
            .progress_chars("█▓░")
            .tick_strings(BRAILLE),
    );
    pb.set_prefix(prefix.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::control::{set_override, unset_override};
    use std::sync::Mutex;

    // `colored`'s override is a process-global flag. `cargo test` runs tests in
    // parallel, so the color-forcing tests below must be serialized against each
    // other or one test's restore clobbers another's window (observed as flaky
    // "saw ANSI escapes" failures). This lock makes them mutually exclusive.
    static COLOR_LOCK: Mutex<()> = Mutex::new(());

    /// Run `body` with color forced off, then restore auto-detection. Holds the
    /// shared lock for the whole window; recovers from a poisoned lock so one
    /// failing assertion doesn't cascade into the others.
    fn with_color_off(body: impl FnOnce()) {
        let _guard = COLOR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_override(false);
        body();
        unset_override();
    }

    #[test]
    fn section_line_fills_to_exact_width_uncolored() {
        with_color_off(|| {
            let line = section_line("decode");
            assert!(line.starts_with("▎ DECODE "));
            let dashes = line.chars().filter(|c| *c == '─').count();
            // Visible cols before the rule: "▎ " (2) + "DECODE" (6) + " " (1) = 9.
            assert_eq!(dashes, SECTION_WIDTH - (2 + "DECODE".len() + 1));
        });
    }

    #[test]
    fn section_line_rule_floors_at_three_for_long_titles() {
        with_color_off(|| {
            // A title longer than SECTION_WIDTH saturates the subtraction to 0,
            // and the `.max(3)` floor keeps a minimal rule.
            let long = "x".repeat(SECTION_WIDTH + 10);
            let dashes = section_line(&long).chars().filter(|c| *c == '─').count();
            assert_eq!(dashes, 3);
        });
    }

    #[test]
    fn kv_line_pads_plain_label() {
        with_color_off(|| {
            // 14-wide padding: "Type" (4) + 10 spaces before the value.
            assert_eq!(kv_line("Type", "JWT", 14), "  Type          JWT");
        });
    }

    #[test]
    fn badge_pads_label_to_four() {
        with_color_off(|| {
            assert_eq!(badge(G_DEBUG, "MED", Color::Yellow), "● MED ");
        });
    }

    #[test]
    fn badge_width_pads_wider_labels() {
        with_color_off(|| {
            // VALID/INVALID share a 7-col column so jwks rows align.
            assert_eq!(badge_width(G_OK, "VALID", Color::Green, 7), "✓ VALID  ");
            assert_eq!(badge_width(G_ERR, "INVALID", Color::Red, 7), "✗ INVALID");
        });
    }

    #[test]
    fn subsection_has_accent_bar() {
        with_color_off(|| {
            assert_eq!(subsection_line("Header"), "▎ Header");
        });
    }
}
