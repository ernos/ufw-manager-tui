//! Pure logic: no process spawning, no file access, no terminal.
//!
//! Everything here is deterministic and unit tested against real `ufw` output captured from
//! `ufw` 0.36.2 on Ubuntu 26.04.

pub mod command;
pub mod explain;
pub mod firewall;
pub mod lockout;
pub mod parse;
pub mod presets;
pub mod risk;
pub mod rule;
pub mod simulate;
pub mod undo;
pub mod util;
