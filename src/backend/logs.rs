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

/**
 * One aggregated row of blocked traffic.
 *
 * Repeated attempts from the same source to the same port and protocol are
 * folded into a single row so a port scan reads as one line instead of
 * thousands.
 *
 * # Fields
 *
 * * `src` (`IpAddr`) - Source address of the blocked packets.
 * * `dst` (`IpAddr`) - Destination address of the blocked packets.
 * * `proto` (`String`) - Lowercase protocol name, e.g. `tcp`.
 * * `dpt` (`u16`) - Destination port.
 * * `iface` (`String`) - Incoming interface the packets arrived on.
 * * `count` (`u64`) - Number of packets aggregated into this row.
 * * `last_seen` (`Instant`) - Monotonic time of the most recent packet.
 */
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
    /**
     * Returns how long ago this aggregated row was last seen.
     *
     * # Arguments
     *
     * * `self` (`&BlockRow`) - The row being read; it is not modified.
     *
     * # Returns
     *
     * `Duration` - Elapsed time since `last_seen`, measured against the current
     * monotonic clock.
     */
    pub fn age(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

/**
 * The aggregation table shared between the reader thread and the UI.
 *
 * Keyed by `(source address, destination port, protocol)` so repeated attempts
 * collapse into one [`BlockRow`].
 */
type Table = HashMap<(IpAddr, u16, String), BlockRow>;

/**
 * A background reader. Dropping it stops the thread.
 *
 * It owns the shared aggregation table, the stop flag and the reader thread
 * handle, so the UI can poll [`BlockMonitor::rows`] while the thread keeps
 * folding new log lines into the table.
 *
 * # Fields
 *
 * * `table` (`Arc<Mutex<Table>>`) - The aggregation table shared with the reader
 *   thread.
 * * `stop` (`Arc<AtomicBool>`) - Flag the reader thread polls; set on drop.
 * * `source` (`String`) - Human-readable name of the log source being read.
 * * `handle` (`Option<JoinHandle<()>>`) - The reader thread, if it was spawned.
 */
pub struct BlockMonitor {
    table: Arc<Mutex<Table>>,
    stop: Arc<AtomicBool>,
    source: String,
    handle: Option<JoinHandle<()>>,
}

impl BlockMonitor {
    /**
     * Starts the background reader thread and returns a handle to its table.
     *
     * When `log_path` is `Some`, a thread tails that file from its current end;
     * when it is `None`, a thread follows `journalctl -k -f`. If the thread
     * cannot be spawned the monitor still exists but stays empty.
     *
     * # Arguments
     *
     * * `log_path` (`Option<PathBuf>`) - Path to `ufw.log` to tail, or `None` to
     *   fall back to the kernel journal.
     *
     * # Returns
     *
     * `BlockMonitor` - A monitor owning the shared table, the stop flag and the
     * reader thread handle.
     *
     * # Notes
     *
     * Spawns an OS thread and, in journal mode, a `journalctl` subprocess.
     */
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

    /**
     * Aggregated rows, busiest first.
     *
     * Rows are sorted by hit count descending, then by destination port, and
     * truncated to 200 entries so the table stays readable during a flood.
     *
     * # Arguments
     *
     * * `self` (`&BlockMonitor`) - The monitor whose table is read; it is not
     *   modified.
     *
     * # Returns
     *
     * `Vec<BlockRow>` - Up to 200 cloned rows, or an empty vector when the table
     * lock is poisoned.
     */
    pub fn rows(&self) -> Vec<BlockRow> {
        let Ok(table) = self.table.lock() else {
            return Vec::new();
        };
        let mut rows: Vec<BlockRow> = table.values().cloned().collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.dpt.cmp(&b.dpt)));
        rows.truncate(200);
        rows
    }

    /**
     * Returns the human-readable name of the log source being read.
     *
     * # Arguments
     *
     * * `self` (`&BlockMonitor`) - The monitor being read; it is not modified.
     *
     * # Returns
     *
     * `&str` - Either the log file path or `journalctl -k`.
     */
    pub fn source(&self) -> &str {
        &self.source
    }

    /**
     * Sums the hit counts of every aggregated row.
     *
     * # Arguments
     *
     * * `self` (`&BlockMonitor`) - The monitor being read; it is not modified.
     *
     * # Returns
     *
     * `u64` - Total blocked packets currently retained, or `0` if the table lock
     * is poisoned.
     */
    pub fn total(&self) -> u64 {
        self.table
            .lock()
            .map(|t| t.values().map(|r| r.count).sum())
            .unwrap_or(0)
    }
}

impl Drop for BlockMonitor {
    /**
     * Signals the reader thread to stop when the monitor goes out of scope.
     *
     * # Arguments
     *
     * * `self` (`&mut BlockMonitor`) - The monitor being dropped; its stop flag
     *   is set and the thread handle is released.
     *
     * # Returns
     *
     * `()` - This function returns no value.
     *
     * # Notes
     *
     * The thread is deliberately not joined: a blocked read on a pipe can take a
     * while, and the thread only holds an `Arc`, so it exits at its next poll.
     */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Do not join: a blocked read on a pipe can take a while, and the thread only holds an
        // Arc. It will exit at its next poll.
        let _ = self.handle.take();
    }
}

/**
 * Parses one log line and folds it into the aggregation table.
 *
 * Lines that are not UFW block events are ignored. Entries older than
 * [`RETENTION`] are pruned on every call, and a repeated
 * `(source, port, protocol)` triple increments the existing row instead of
 * adding a new one.
 *
 * # Arguments
 *
 * * `table` (`&Arc<Mutex<Table>>`) - Shared aggregation table to update.
 * * `line` (`&str`) - One raw log line, without its trailing newline.
 *
 * # Returns
 *
 * `()` - This function returns no value. Parse failures and a poisoned lock are
 * silently ignored.
 */
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

/**
 * Follows a log file from its current end until asked to stop.
 *
 * Only new lines are read, so a year of history is not replayed. The loop
 * sleeps briefly when there is nothing to read and exits when `stop` is set.
 *
 * # Arguments
 *
 * * `path` (`PathBuf`) - Log file to tail.
 * * `table` (`Arc<Mutex<Table>>`) - Shared aggregation table to update.
 * * `stop` (`Arc<AtomicBool>`) - Flag polled between reads; `true` ends the loop.
 *
 * # Returns
 *
 * `()` - This function returns no value. A file that cannot be opened ends the
 * thread immediately.
 *
 * # Notes
 *
 * Blocking I/O on a background thread; read errors are retried after a short
 * sleep rather than reported.
 */
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

/**
 * Follows the kernel journal through `journalctl -k -f` until asked to stop.
 *
 * The child process is killed and reaped when the loop ends, whether because
 * `stop` was set or because the pipe closed.
 *
 * # Arguments
 *
 * * `table` (`Arc<Mutex<Table>>`) - Shared aggregation table to update.
 * * `stop` (`Arc<AtomicBool>`) - Flag polled between lines; `true` ends the loop.
 *
 * # Returns
 *
 * `()` - This function returns no value. A failed spawn or a missing stdout pipe
 * ends the thread immediately.
 *
 * # Notes
 *
 * Spawns a subprocess and blocks on its stdout; `LC_ALL=C` is set so the log
 * lines match the parser.
 */
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

    /**
     * Builds a realistic `[UFW BLOCK]` kernel log line for the tests.
     *
     * # Arguments
     *
     * * `src` (`&str`) - Source address to embed.
     * * `dpt` (`u16`) - Destination port to embed.
     * * `proto` (`&str`) - Protocol token to embed, e.g. `TCP`.
     *
     * # Returns
     *
     * `String` - A single log line without a trailing newline.
     */
    fn line(src: &str, dpt: u16, proto: &str) -> String {
        format!(
            "Oct 30 08:23:50 host kernel: [1.0] [UFW BLOCK] IN=eno1 OUT= MAC=aa SRC={src} DST=192.168.1.19 LEN=60 PROTO={proto} SPT=51000 DPT={dpt}"
        )
    }

    /**
     * Creates an empty aggregation table for the tests.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `Arc<Mutex<Table>>` - A fresh, empty shared table.
     */
    fn table() -> Arc<Mutex<Table>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    /**
     * Verifies that repeated attempts from one source collapse into one row.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
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
    /**
     * Verifies that lines which are not UFW block events are ignored.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn non_block_lines_are_ignored() {
        let table = table();
        record(&table, "Oct 30 08:23:50 host apparmor=\"DENIED\"");
        assert!(table.lock().unwrap().is_empty());
    }

    #[test]
    /**
     * Verifies that [`BlockMonitor::rows`] sorts busiest first and that
     * [`BlockMonitor::total`] sums every row.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
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
    /**
     * Verifies that starting a monitor on a nonexistent log file is harmless.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn a_missing_log_source_does_not_panic() {
        let monitor = BlockMonitor::start(Some(PathBuf::from("/definitely/not/a/log")));
        assert!(monitor.rows().is_empty());
    }
}
