//! Live tail of blocked packets.
//!
//! Reads `/var/log/ufw.log` when it is readable (the user is usually in the `adm` group), otherwise
//! falls back to `journalctl -k -f`. Events are aggregated by `(source, protocol, port)` so a port
//! scan produces one readable row instead of ten thousand lines.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::core::parse::parse_ufw_log_line;

/// Entries older than this are pruned so the table cannot grow without bound.
const RETENTION: Duration = Duration::from_secs(900);

#[derive(Debug, Clone)]
pub struct BlockRow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: String,
    pub dpt: u16,
    pub iface: String,
    pub count: u64,
    pub last_seen: Instant,
}

impl BlockRow {
    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

type Table = HashMap<(IpAddr, u16, String), BlockRow>;

/// A background reader. Dropping it stops the thread.
pub struct BlockMonitor {
    table: Arc<Mutex<Table>>,
    stop: Arc<AtomicBool>,
    source: String,
    handle: Option<JoinHandle<()>>,
}

impl BlockMonitor {
    pub fn start(log_path: Option<PathBuf>) -> Self {
        let table: Arc<Mutex<Table>> = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let (source, handle) = match log_path {
            Some(path) => {
                let thread_table = Arc::clone(&table);
                let thread_stop = Arc::clone(&stop);
                let source = path.display().to_string();
                let handle = std::thread::Builder::new()
                    .name("ufw-log-tail".into())
                    .spawn(move || tail_file(path, thread_table, thread_stop))
                    .ok();
                (source, handle)
            }
            None => {
                let thread_table = Arc::clone(&table);
                let thread_stop = Arc::clone(&stop);
                let handle = std::thread::Builder::new()
                    .name("ufw-journal-tail".into())
                    .spawn(move || tail_journal(thread_table, thread_stop))
                    .ok();
                ("journalctl -k".to_string(), handle)
            }
        };

        Self {
            table,
            stop,
            source,
            handle,
        }
    }

    /// Aggregated rows, busiest first.
    pub fn rows(&self) -> Vec<BlockRow> {
        let Ok(table) = self.table.lock() else {
            return Vec::new();
        };
        let mut rows: Vec<BlockRow> = table.values().cloned().collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.dpt.cmp(&b.dpt)));
        rows.truncate(200);
        rows
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn total(&self) -> u64 {
        self.table
            .lock()
            .map(|t| t.values().map(|r| r.count).sum())
            .unwrap_or(0)
    }
}

impl Drop for BlockMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Do not join: a blocked read on a pipe can take a while, and the thread only holds an
        // Arc. It will exit at its next poll.
        let _ = self.handle.take();
    }
}

fn record(table: &Arc<Mutex<Table>>, line: &str) {
    let Some(event) = parse_ufw_log_line(line) else {
        return;
    };
    let Ok(mut table) = table.lock() else {
        return;
    };
    let key = (event.src, event.dpt, event.proto.clone());
    let now = Instant::now();
    table.retain(|_, row| now.duration_since(row.last_seen) < RETENTION);
    table
        .entry(key)
        .and_modify(|row| {
            row.count += 1;
            row.last_seen = now;
            row.iface = event.iface.clone();
        })
        .or_insert(BlockRow {
            src: event.src,
            dst: event.dst,
            proto: event.proto,
            dpt: event.dpt,
            iface: event.iface,
            count: 1,
            last_seen: now,
        });
}

fn tail_file(path: PathBuf, table: Arc<Mutex<Table>>, stop: Arc<AtomicBool>) {
    let Ok(mut file) = std::fs::File::open(&path) else {
        return;
    };
    // Only show what happens from now on; replaying a year of logs is not useful.
    let _ = file.seek(SeekFrom::End(0));
    let mut buffer = String::new();
    let mut reader = BufReader::new(file);

    while !stop.load(Ordering::Relaxed) {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => std::thread::sleep(Duration::from_millis(300)),
            Ok(_) => record(&table, buffer.trim_end()),
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn tail_journal(table: Arc<Mutex<Table>>, stop: Arc<AtomicBool>) {
    let child = Command::new("journalctl")
        .args(["-k", "-f", "-n", "200", "-o", "cat"])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return;
    };
    let Some(stdout) = child.stdout.take() else {
        return;
    };
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match line {
            Ok(line) => record(&table, &line),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(src: &str, dpt: u16, proto: &str) -> String {
        format!(
            "Oct 30 08:23:50 host kernel: [1.0] [UFW BLOCK] IN=eno1 OUT= MAC=aa SRC={src} DST=192.168.1.19 LEN=60 PROTO={proto} SPT=51000 DPT={dpt}"
        )
    }

    fn table() -> Arc<Mutex<Table>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn aggregates_repeated_attempts_into_one_row() {
        let table = table();
        for _ in 0..5 {
            record(&table, &line("45.155.205.233", 22, "TCP"));
        }
        record(&table, &line("91.240.118.11", 8080, "TCP"));

        let rows = table.lock().unwrap();
        assert_eq!(rows.len(), 2);
        let ssh = rows.values().find(|r| r.dpt == 22).unwrap();
        assert_eq!(ssh.count, 5);
        assert_eq!(ssh.proto, "tcp");
        assert_eq!(ssh.iface, "eno1");
    }

    #[test]
    fn non_block_lines_are_ignored() {
        let table = table();
        record(&table, "Oct 30 08:23:50 host apparmor=\"DENIED\"");
        assert!(table.lock().unwrap().is_empty());
    }

    #[test]
    fn rows_come_back_busiest_first() {
        let table = table();
        record(&table, &line("1.2.3.4", 22, "TCP"));
        for _ in 0..3 {
            record(&table, &line("5.6.7.8", 3306, "TCP"));
        }
        let monitor = BlockMonitor {
            table,
            stop: Arc::new(AtomicBool::new(false)),
            source: "test".into(),
            handle: None,
        };
        let rows = monitor.rows();
        assert_eq!(rows[0].dpt, 3306);
        assert_eq!(monitor.total(), 4);
    }

    #[test]
    fn a_missing_log_source_does_not_panic() {
        let monitor = BlockMonitor::start(Some(PathBuf::from("/definitely/not/a/log")));
        assert!(monitor.rows().is_empty());
    }
}
