//! Process hardening for `rbkeeperd run` (issue #83, "RAM-only").
//!
//! Applied before any secret exists in the process. Each step failing is fatal:
//! the daemon refuses to unlock rather than hold a token in swappable or dumpable
//! memory. None of this defends against root on the host — root can read the
//! daemon's memory (owner note on #83); it closes the paths a non-root process,
//! a crash or the swap device would otherwise have.
//!
//! Linux: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE 0`, `mlockall`, and no plain swap in
//! `/proc/swaps`. macOS has no `mlockall` and no `/proc` (README "Limits", macOS):
//! `RLIMIT_CORE=0`, `ptrace(PT_DENY_ATTACH)`, `mlock` on the secret buffers this
//! crate owns ([`lock_in_ram`]), and `vm.swapusage` must say the swap is encrypted.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("rbkeeperd supports Linux and macOS only");

use std::fmt;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

#[derive(Debug)]
pub enum HardeningError {
    Syscall(&'static str, std::io::Error),
    /// An active swap device that is not dm-crypt.
    PlainSwap(String),
    /// macOS: `vm.swapusage` does not report the swap as encrypted.
    UnencryptedSwap(String),
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardeningError::Syscall(what, e) => write!(f, "{} failed: {}", what, e),
            HardeningError::PlainSwap(dev) => write!(
                f,
                "active swap {} is not encrypted; turn swap off or put it on dm-crypt (see DEPLOY.md)",
                dev
            ),
            HardeningError::UnencryptedSwap(usage) => write!(
                f,
                "swap is not encrypted (vm.swapusage: {}); macOS encrypts swap unless that was turned off (see DEPLOY.md)",
                usage
            ),
        }
    }
}

impl std::error::Error for HardeningError {}

fn check(what: &'static str, rc: libc::c_int) -> Result<(), HardeningError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(HardeningError::Syscall(what, std::io::Error::last_os_error()))
    }
}

fn no_core_files() -> Result<(), HardeningError> {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    check("setrlimit(RLIMIT_CORE, 0)", unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) })
}

/// No core dumps (`RLIMIT_CORE=0`), not dumpable / not ptrace-attachable by the same
/// uid (`PR_SET_DUMPABLE 0`), and every page — current and future — locked in RAM
/// (`mlockall(MCL_CURRENT|MCL_FUTURE)`), so nothing the daemon holds can be paged out.
/// Returns what was applied, for the log.
#[cfg(target_os = "linux")]
pub fn harden_process() -> Result<&'static str, HardeningError> {
    no_core_files()?;
    check("prctl(PR_SET_DUMPABLE, 0)", unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    check("mlockall(MCL_CURRENT|MCL_FUTURE)", unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) })?;
    Ok("RLIMIT_CORE=0, PR_SET_DUMPABLE 0, mlockall(MCL_CURRENT|MCL_FUTURE)")
}

/// No core dumps (`RLIMIT_CORE=0`) and no debugger (`ptrace(PT_DENY_ATTACH)`: an
/// attach, or a later `PT_ATTACH`, kills the process). macOS has no `mlockall`;
/// the buffers this crate owns are `mlock`ed one by one ([`lock_in_ram`]).
#[cfg(target_os = "macos")]
pub fn harden_process() -> Result<&'static str, HardeningError> {
    no_core_files()?;
    check("ptrace(PT_DENY_ATTACH)", unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) })?;
    Ok("RLIMIT_CORE=0, ptrace(PT_DENY_ATTACH), mlock on the daemon's own secret buffers (no mlockall on macOS)")
}

/// Keep the pages under `buf` out of swap. On Linux `mlockall(MCL_FUTURE)` already
/// covers every page, so this does nothing. On macOS it `mlock`s the page range of
/// a secret buffer this crate owns (the unlock payload, the token and password, the
/// decrypted vault). Pages stay locked until exit. A failed `mlock` is logged once,
/// not fatal: `check_swap` has already refused unencrypted swap, so a page that
/// does get paged out lands only in encrypted swap.
#[cfg(target_os = "linux")]
#[inline]
pub fn lock_in_ram(_buf: &[u8]) {}

#[cfg(target_os = "macos")]
pub fn lock_in_ram(buf: &[u8]) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if buf.is_empty() {
        return;
    }
    let page = match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        n if n > 0 => n as usize,
        _ => 4096,
    };
    let start = buf.as_ptr() as usize & !(page - 1);
    let end = (buf.as_ptr() as usize + buf.len()).div_ceil(page) * page;
    if unsafe { libc::mlock(start as *const libc::c_void, end - start) } != 0 && !WARNED.swap(true, Ordering::Relaxed) {
        log::warn!("mlock of a secret buffer failed: {}; it may be paged out to the (encrypted) swap", std::io::Error::last_os_error());
    }
}

/// Refuse to run with an active swap device that is not encrypted. Swap is a page
/// destination `mlockall` already rules out, but a failed or later-dropped lock
/// would leave the plain device as the place a secret lands on disk.
#[cfg(target_os = "linux")]
pub fn check_swap() -> Result<(), HardeningError> {
    let swaps = fs::read_to_string("/proc/swaps").unwrap_or_default();
    check_swap_table(&swaps, Path::new("/sys/block"))
}

/// `/proc/swaps` lines after the header; the first column is the device or file.
#[cfg(target_os = "linux")]
pub fn check_swap_table(proc_swaps: &str, sys_block: &Path) -> Result<(), HardeningError> {
    for line in proc_swaps.lines().skip(1) {
        let Some(dev) = line.split_whitespace().next() else { continue };
        if !is_dm_crypt(dev, sys_block) {
            return Err(HardeningError::PlainSwap(dev.to_string()));
        }
    }
    Ok(())
}

/// A swap device counts as encrypted when it is a device-mapper node whose uuid
/// starts with `CRYPT-` (cryptsetup's convention). A swap *file* never counts.
#[cfg(target_os = "linux")]
fn is_dm_crypt(dev: &str, sys_block: &Path) -> bool {
    let real = fs::canonicalize(dev).unwrap_or_else(|_| dev.into());
    let Some(name) = real.file_name().and_then(|n| n.to_str()) else { return false };
    if !name.starts_with("dm-") {
        return false;
    }
    fs::read_to_string(sys_block.join(name).join("dm").join("uuid"))
        .map(|u| u.trim_start().starts_with("CRYPT-"))
        .unwrap_or(false)
}

/// Refuse to run unless `sysctl vm.swapusage` reports the swap as `(encrypted)`.
/// macOS adds swap files on demand, so "no swap now" is not enough: the flag must
/// be set even while the total is 0. Every macOS since 10.7 encrypts swap.
#[cfg(target_os = "macos")]
pub fn check_swap() -> Result<(), HardeningError> {
    let mut usage: libc::xsw_usage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xsw_usage>();
    let rc = unsafe {
        libc::sysctlbyname(
            c"vm.swapusage".as_ptr(),
            (&mut usage as *mut libc::xsw_usage).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    check("sysctlbyname(vm.swapusage)", rc)?;
    check_swapusage(usage.xsu_total, usage.xsu_used, usage.xsu_encrypted != 0)
}

/// The decision behind the macOS `check_swap`, kept apart so it is tested on any host.
#[cfg(any(target_os = "macos", test))]
pub fn check_swapusage(total: u64, used: u64, encrypted: bool) -> Result<(), HardeningError> {
    if encrypted {
        return Ok(());
    }
    let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
    Err(HardeningError::UnencryptedSwap(format!("total = {:.2}M  used = {:.2}M, not (encrypted)", mb(total), mb(used))))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const HEADER: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

    #[test]
    fn no_swap_passes() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_swap_table(HEADER, dir.path()).is_ok());
        assert!(check_swap_table("", dir.path()).is_ok());
    }

    #[test]
    fn plain_partitions_and_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let t = format!("{}/dev/sda2 partition 8388604 0 -2\n", HEADER);
        assert!(matches!(check_swap_table(&t, dir.path()), Err(HardeningError::PlainSwap(d)) if d == "/dev/sda2"));
        let t = format!("{}/swapfile file 1048572 0 -2\n", HEADER);
        assert!(check_swap_table(&t, dir.path()).is_err());
    }

    #[test]
    fn dm_crypt_swap_passes_and_other_dm_does_not() {
        let dir = tempfile::tempdir().unwrap();
        for (name, uuid) in [("dm-0", "CRYPT-PLAIN-swap\n"), ("dm-1", "LVM-abc\n")] {
            fs::create_dir_all(dir.path().join(name).join("dm")).unwrap();
            fs::write(dir.path().join(name).join("dm").join("uuid"), uuid).unwrap();
        }
        // /proc/swaps names the dm node directly (`/dev/dm-0`); canonicalize of a
        // missing path falls back to the name itself.
        let t = format!("{}/dev/dm-0 partition 8388604 0 -2\n", HEADER);
        assert!(check_swap_table(&t, dir.path()).is_ok());
        let t = format!("{}/dev/dm-1 partition 8388604 0 -2\n", HEADER);
        assert!(check_swap_table(&t, dir.path()).is_err());
    }
}

#[cfg(test)]
mod swapusage_tests {
    use super::*;

    #[test]
    fn macos_swap_must_be_encrypted_even_when_empty() {
        assert!(check_swapusage(0, 0, true).is_ok());
        assert!(check_swapusage(2 << 30, 1 << 30, true).is_ok());
        assert!(matches!(check_swapusage(0, 0, false), Err(HardeningError::UnencryptedSwap(_))));
        let e = check_swapusage(1 << 30, 0, false).unwrap_err().to_string();
        assert!(e.contains("total = 1024.00M") && e.contains("not (encrypted)"), "{}", e);
    }
}
