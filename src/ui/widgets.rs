//! Small reusable widgets.

use ratatui::layout::Rect;

/**
 * A single-line text input with a character cursor.
 *
 * The cursor is tracked in characters rather than bytes so multi-byte text is
 * never split, and every editing operation keeps it within the value's bounds.
 *
 * # Fields
 *
 * * `value` (`String`) - The text currently held by the input.
 * * `cursor` (`usize`) - Cursor position, in characters rather than bytes.
 */
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    value: String,
    /// Cursor position, in characters rather than bytes.
    cursor: usize,
}

impl TextInput {
    /**
     * Creates an input holding `value`, with the cursor at the end.
     *
     * # Arguments
     *
     * * `value` (`impl Into<String>`) - The initial text.
     *
     * # Returns
     *
     * A `TextInput` whose cursor sits after the last character.
     */
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.chars().count();
        Self { value, cursor }
    }

    /**
     * Returns the current text.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The input being read.
     *
     * # Returns
     *
     * A `&str` borrowing the stored value.
     */
    pub fn value(&self) -> &str {
        &self.value
    }

    /**
     * Reports whether the input holds only whitespace.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The input being read.
     *
     * # Returns
     *
     * `true` when the trimmed value is empty; otherwise, `false`.
     */
    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }

    /**
     * Replaces the text and moves the cursor to the end.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     * * `value` (`impl Into<String>`) - The new text.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    /**
     * Empties the input and resets the cursor to the start.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    /**
     * Inserts a character at the cursor and advances the cursor past it.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     * * `character` (`char`) - The character to insert.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn insert(&mut self, character: char) {
        let byte = self.byte_offset(self.cursor);
        self.value.insert(byte, character);
        self.cursor += 1;
    }

    /**
     * Deletes the character before the cursor.
     *
     * Does nothing when the cursor is already at the start.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let byte = self.byte_offset(self.cursor);
        self.value.remove(byte);
    }

    /**
     * Deletes the character under the cursor.
     *
     * Does nothing when the cursor is already at the end of the value.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn delete(&mut self) {
        if self.cursor >= self.value.chars().count() {
            return;
        }
        let byte = self.byte_offset(self.cursor);
        self.value.remove(byte);
    }

    /**
     * Moves the cursor one character to the left, stopping at the start.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /**
     * Moves the cursor one character to the right, stopping at the end.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn right(&mut self) {
        if self.cursor < self.value.chars().count() {
            self.cursor += 1;
        }
    }

    /**
     * Moves the cursor to the start of the value.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /**
     * Moves the cursor to the end of the value.
     *
     * # Arguments
     *
     * * `self` (`&mut self`) - The input being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    /**
     * Splits the value around the cursor so the renderer can draw a block
     * cursor.
     *
     * The character under the cursor is returned separately; when the cursor is
     * at the end of the value a space is substituted so the cursor is still
     * visible.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The input being read.
     *
     * # Returns
     *
     * A `(String, char, String)` of the text before the cursor, the character
     * under the cursor, and the text after it.
     */
    pub fn parts(&self) -> (String, char, String) {
        let chars: Vec<char> = self.value.chars().collect();
        let before: String = chars.iter().take(self.cursor).collect();
        let at = chars.get(self.cursor).copied().unwrap_or(' ');
        let after: String = chars.iter().skip(self.cursor + 1).collect();
        (before, at, after)
    }

    /**
     * Converts a character index into a byte offset in the value.
     *
     * This is what lets the editing methods index a `String` safely when the
     * text contains multi-byte characters. An index past the end maps to the
     * value's length.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The input being read.
     * * `chars` (`usize`) - The character index to convert.
     *
     * # Returns
     *
     * The `usize` byte offset of that character, or the value's byte length
     * when the index is out of range.
     */
    fn byte_offset(&self, chars: usize) -> usize {
        self.value
            .char_indices()
            .nth(chars)
            .map(|(index, _)| index)
            .unwrap_or(self.value.len())
    }
}

/**
 * Returns a rectangle centred in `area`, used for dialogs.
 *
 * The width is a percentage of `area` clamped to 10–100, then clamped to at
 * least 20 columns and at most the area's width. The height is clamped to the
 * area's height. The result is always positioned inside `area`.
 *
 * # Arguments
 *
 * * `area` (`Rect`) - The region to centre within.
 * * `width_percent` (`u16`) - The desired width as a percentage of `area`.
 * * `height` (`u16`) - The desired height in rows.
 *
 * # Returns
 *
 * A `Rect` centred horizontally and vertically inside `area`.
 */
pub fn centered_rect(area: Rect, width_percent: u16, height: u16) -> Rect {
    let width = area.width.saturating_mul(width_percent.clamp(10, 100)) / 100;
    let width = width.clamp(20, area.width.max(20));
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Checks that typing appends characters and backspace removes the last one.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong value.
     */
    fn typing_and_backspacing_behave() {
        let mut input = TextInput::default();
        for c in "22/tcp".chars() {
            input.insert(c);
        }
        assert_eq!(input.value(), "22/tcp");
        input.backspace();
        assert_eq!(input.value(), "22/tc");
    }

    #[test]
    /**
     * Checks that cursor movement never leaves the bounds of the value.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong cursor.
     */
    fn the_cursor_moves_within_bounds() {
        let mut input = TextInput::new("abc");
        input.home();
        assert_eq!(input.parts().0, "");
        input.left();
        assert_eq!(input.parts().0, "");
        input.right();
        input.right();
        input.right();
        input.right();
        assert_eq!(input.value(), "abc");
    }

    #[test]
    /**
     * Checks that inserted characters land at the cursor position.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong value.
     */
    fn insertion_happens_at_the_cursor() {
        let mut input = TextInput::new("ac");
        input.left();
        input.insert('b');
        assert_eq!(input.value(), "abc");
    }

    #[test]
    /**
     * Checks that delete removes the character under the cursor.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong value.
     */
    fn delete_removes_the_character_under_the_cursor() {
        let mut input = TextInput::new("abc");
        input.home();
        input.delete();
        assert_eq!(input.value(), "bc");
    }

    #[test]
    /**
     * Checks that editing multi-byte text never splits a character.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong value.
     */
    fn multibyte_text_is_not_split() {
        let mut input = TextInput::new("héllo");
        input.backspace();
        assert_eq!(input.value(), "héll");
        input.insert('ö');
        assert_eq!(input.value(), "héllö");
    }

    #[test]
    /**
     * Checks that `parts` splits the value around the character at the cursor.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong split.
     */
    fn parts_expose_the_block_cursor() {
        let mut input = TextInput::new("abc");
        input.home();
        let (before, at, after) = input.parts();
        assert_eq!(before, "");
        assert_eq!(at, 'a');
        assert_eq!(after, "bc");
    }

    #[test]
    /**
     * Checks that a centred rectangle never extends past the given area.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the rect overflows.
     */
    fn centred_rects_stay_inside_the_area() {
        let area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let rect = centered_rect(area, 60, 10);
        assert!(rect.x + rect.width <= area.width);
        assert!(rect.y + rect.height <= area.height);
    }
}
