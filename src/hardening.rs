//! Process hardening for `rbkeeperd run` (issue #83, "RAM-only").
//!
//! Applied before any secret exists in the process. Each step failing is fatal:
//! the daemon refuses to unlock rather than hold a token in swappable or dumpable
//! memory. None of this defends against root on the host — root can read the
//! daemon's memory (owner note on #83); it closes the paths a non-root process,
//! a crash or the swap device would otherwise have.

use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum HardeningError {
    Syscall(&'static str, std::io::Error),
    /// An active swap device that is not dm-crypt.
    PlainSwap(String),
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

/// No core dumps (`RLIMIT_CORE=0`), not dumpable / not ptrace-attachable by the same
/// uid (`PR_SET_DUMPABLE 0`), and every page — current and future — locked in RAM
/// (`mlockall(MCL_CURRENT|MCL_FUTURE)`), so nothing the daemon holds can be paged out.
pub fn harden_process() -> Result<(), HardeningError> {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    check("setrlimit(RLIMIT_CORE, 0)", unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) })?;
    check("prctl(PR_SET_DUMPABLE, 0)", unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    check("mlockall(MCL_CURRENT|MCL_FUTURE)", unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) })?;
    Ok(())
}

/// Refuse to run with an active swap device that is not encrypted. Swap is a page
/// destination `mlockall` already rules out, but a failed or later-dropped lock
/// would leave the plain device as the place a secret lands on disk.
pub fn check_swap() -> Result<(), HardeningError> {
    let swaps = fs::read_to_string("/proc/swaps").unwrap_or_default();
    check_swap_table(&swaps, Path::new("/sys/block"))
}

/// `/proc/swaps` lines after the header; the first column is the device or file.
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

#[cfg(test)]
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
