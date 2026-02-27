//! Shared SDK for Aeris WASM adapter plugins.
//!
//! This crate provides the common boilerplate every adapter needs:
//! memory management, host communication, command execution, logging,
//! JSON serialization helpers, and the domain types that the Aeris host
//! expects adapters to speak.
//!
//! # Quick start
//!
//! In your adapter's `lib.rs`:
//! ```ignore
//! // Re-export so the WASM binary exposes allocate/deallocate to the host.
//! pub use aeris_adapter_sdk::{allocate, deallocate};
//!
//! use aeris_adapter_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn adapter_init() {
//!     log_info("my adapter initialized");
//! }
//! ```

pub use serde;
pub use serde_json;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Host imports
// ---------------------------------------------------------------------------

extern "C" {
    /// Execute a shell command on the host.
    ///
    /// `cmd_ptr`/`cmd_len` point to a JSON-encoded [`ExecRequest`].
    /// Returns a fat pointer (i64) to a JSON-encoded [`ExecResult`].
    fn host_exec(cmd_ptr: i32, cmd_len: i32) -> i64;

    /// Log a message on the host.
    ///
    /// Log levels: 0 = trace, 1 = debug, 2 = info, 3 = warn, 4 = error.
    fn host_log(level: i32, msg_ptr: i32, msg_len: i32);
}

// ---------------------------------------------------------------------------
// Memory exports (required by host)
// ---------------------------------------------------------------------------

/// Allocate `size` bytes of WASM linear memory and return a pointer.
///
/// The host calls this to reserve space before writing data into the
/// adapter's memory (e.g. function arguments). Adapters **must** re-export
/// this symbol so it appears in the WASM binary:
/// ```ignore
/// pub use aeris_adapter_sdk::{allocate, deallocate};
/// ```
#[no_mangle]
pub extern "C" fn allocate(size: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(size, 1).unwrap();
    unsafe { std::alloc::alloc(layout) }
}

/// Free a previously allocated region of `size` bytes at `ptr`.
///
/// The host calls this to release memory it allocated via [`allocate`].
#[no_mangle]
pub extern "C" fn deallocate(ptr: *mut u8, size: usize) {
    let layout = std::alloc::Layout::from_size_align(size, 1).unwrap();
    unsafe { std::alloc::dealloc(ptr, layout) }
}

// ---------------------------------------------------------------------------
// Fat pointer helpers (internal)
// ---------------------------------------------------------------------------

fn fat_ptr(ptr: u32, len: u32) -> i64 {
    ((ptr as i64) << 32) | (len as i64)
}

fn split_fat_ptr(fat: i64) -> (u32, u32) {
    let ptr = (fat >> 32) as u32;
    let len = (fat & 0xFFFF_FFFF) as u32;
    (ptr, len)
}

// ---------------------------------------------------------------------------
// Input / output helpers
// ---------------------------------------------------------------------------

/// Read a UTF-8 string from WASM linear memory at `(ptr, len)`.
pub fn read_input(ptr: i32, len: i32) -> String {
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    String::from_utf8_lossy(slice).into_owned()
}

fn read_fat_ptr(fat: i64) -> String {
    let (ptr, len) = split_fat_ptr(fat);
    if len == 0 {
        return String::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    String::from_utf8_lossy(slice).into_owned()
}

/// Serialize `value` to JSON, copy it into WASM memory, and return a fat
/// pointer (i64) the host can read.
pub fn return_json<T: Serialize>(value: &T) -> i64 {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    let bytes = json.into_bytes();
    let len = bytes.len();
    let ptr = allocate(len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    }
    fat_ptr(ptr as u32, len as u32)
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Log an informational message (level 2) to the host.
pub fn log_info(msg: &str) {
    unsafe {
        host_log(2, msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Log a warning message (level 3) to the host.
pub fn log_warn(msg: &str) {
    unsafe {
        host_log(3, msg.as_ptr() as i32, msg.len() as i32);
    }
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

/// JSON payload sent to `host_exec` describing the command to run.
#[derive(Serialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

/// JSON payload returned by `host_exec` with the command's output.
#[derive(Deserialize, Default)]
pub struct ExecResult {
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: i32,
}

/// Execute a shell command on the host and return its result.
pub fn exec_command(command: &str, args: &[&str]) -> ExecResult {
    let req = ExecRequest {
        command: command.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
    };
    let json = serde_json::to_string(&req).unwrap_or_default();
    let fat = unsafe { host_exec(json.as_ptr() as i32, json.len() as i32) };
    let result_str = read_fat_ptr(fat);
    serde_json::from_str(&result_str).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A package as returned by search, list, or install operations.
#[derive(Serialize, Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub version: String,
    pub adapter_id: String,
    pub description: Option<String>,
    pub size: Option<u64>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub installed: bool,
    pub update_available: bool,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub icon_url: Option<String>,
}

/// An installed package with additional metadata.
#[derive(Serialize, Deserialize)]
pub struct InstalledPackage {
    pub package: Package,
    pub installed_at: String,
    pub install_size: u64,
    pub install_path: Option<String>,
    pub pinned: bool,
    pub auto_installed: bool,
    pub is_healthy: bool,
    pub profile: Option<String>,
}

/// Result of an install or update operation for a single package.
#[derive(Serialize)]
pub struct InstallResult {
    pub package_name: String,
    pub package_id: String,
    pub version: String,
    pub success: bool,
    pub error: Option<String>,
}

/// An available update for an installed package.
#[derive(Serialize, Deserialize)]
pub struct Update {
    pub package: Package,
    pub current_version: String,
    pub new_version: String,
    pub download_size: Option<u64>,
    pub is_security: bool,
    pub changelog_url: Option<String>,
}

/// Input for `adapter_search`.
#[derive(Deserialize)]
pub struct SearchInput {
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub mode: String,
}

/// Input for `adapter_install`, `adapter_remove`, and `adapter_update`.
#[derive(Deserialize)]
pub struct PackagesWithMode {
    pub packages: Vec<Package>,
    #[serde(default)]
    pub mode: String,
}

/// Input for `adapter_list_installed` and similar mode-only operations.
#[derive(Deserialize)]
pub struct ModeInput {
    #[serde(default)]
    pub mode: String,
}

/// Response from `adapter_info`.
#[derive(Serialize)]
pub struct AdapterInfoResponse {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
}

/// Response from `adapter_capabilities`.
#[derive(Serialize)]
pub struct CapabilitiesResponse {
    pub can_search: bool,
    pub can_install: bool,
    pub can_remove: bool,
    pub can_update: bool,
    pub can_list: bool,
    pub can_list_updates: bool,
    pub can_sync: bool,
    pub can_run: bool,
    pub supports_user_packages: bool,
    pub supports_system_packages: bool,
}

/// Response from `adapter_health_check`.
#[derive(Serialize)]
pub struct HealthResponse {
    pub healthy: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Parse a human-readable size string into bytes.
///
/// Handles both spaced (`"150 MB"`) and unspaced (`"150MB"`) formats.
/// Recognized units: B, KB/KiB/K, MB/MiB/M, GB/GiB/G (case-insensitive).
///
/// Returns `None` for empty strings or unrecognized formats.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if let Some((n, u)) = s.split_once(char::is_whitespace) {
        (n.trim(), u.trim())
    } else {
        let pos = s
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len());
        (&s[..pos], s[pos..].trim())
    };
    let num: f64 = num_str.parse().ok()?;
    let multiplier: u64 = match unit.to_lowercase().as_str() {
        "b" => 1,
        "kib" | "kb" | "k" => 1024,
        "mib" | "mb" | "m" => 1024 * 1024,
        "gib" | "gb" | "g" => 1024 * 1024 * 1024,
        _ => return None,
    };
    Some((num * multiplier as f64) as u64)
}

/// Strip ANSI escape sequences (e.g. color codes) from a string.
pub fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}
