//! Small reusable widgets.

use ratatui::layout::Rect;

/// A single-line text input with a character cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextInput {
    value: String,
    /// Cursor position, in characters rather than bytes.
    cursor: usize,
}

impl TextInput {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.chars().count();
        Self { value, cursor }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }

    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    pub fn insert(&mut self, character: char) {
        let byte = self.byte_offset(self.cursor);
        self.value.insert(byte, character);
        self.cursor += 1;
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let byte = self.byte_offset(self.cursor);
        self.value.remove(byte);
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.value.chars().count() {
            return;
        }
        let byte = self.byte_offset(self.cursor);
        self.value.remove(byte);
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        if self.cursor < self.value.chars().count() {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    /// Splits the value around the cursor so the renderer can draw a block cursor.
    pub fn parts(&self) -> (String, char, String) {
        let chars: Vec<char> = self.value.chars().collect();
        let before: String = chars.iter().take(self.cursor).collect();
        let at = chars.get(self.cursor).copied().unwrap_or(' ');
        let after: String = chars.iter().skip(self.cursor + 1).collect();
        (before, at, after)
    }

    fn byte_offset(&self, chars: usize) -> usize {
        self.value
            .char_indices()
            .nth(chars)
            .map(|(index, _)| index)
            .unwrap_or(self.value.len())
    }
}

/// A rectangle centred in `area`, used for dialogs.
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
    fn insertion_happens_at_the_cursor() {
        let mut input = TextInput::new("ac");
        input.left();
        input.insert('b');
        assert_eq!(input.value(), "abc");
    }

    #[test]
    fn delete_removes_the_character_under_the_cursor() {
        let mut input = TextInput::new("abc");
        input.home();
        input.delete();
        assert_eq!(input.value(), "bc");
    }

    #[test]
    fn multibyte_text_is_not_split() {
        let mut input = TextInput::new("héllo");
        input.backspace();
        assert_eq!(input.value(), "héll");
        input.insert('ö');
        assert_eq!(input.value(), "héllö");
    }

    #[test]
    fn parts_expose_the_block_cursor() {
        let mut input = TextInput::new("abc");
        input.home();
        let (before, at, after) = input.parts();
        assert_eq!(before, "");
        assert_eq!(at, 'a');
        assert_eq!(after, "bc");
    }

    #[test]
    fn centred_rects_stay_inside_the_area() {
        let area = ratatui::layout::Rect::new(0, 0, 100, 40);
        let rect = centered_rect(area, 60, 10);
        assert!(rect.x + rect.width <= area.width);
        assert!(rect.y + rect.height <= area.height);
    }
}
