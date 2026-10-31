//! The boot id and host name `run` puts in its `unlock_request` and `device_info`.
//!
//! Linux reads them from `/proc`. macOS takes the boot id from
//! `kern.bootsessionuuid`, lowercased: the server accepts only a lowercase UUID
//! (remote-browser-service `server/headless_keeper.py`), and macOS prints it upper.

/// This boot's id: a new value after every reboot, so every boot needs an approval.
#[cfg(target_os = "linux")]
pub fn boot_id() -> Result<String, String> {
    read_trimmed("/proc/sys/kernel/random/boot_id")
}

#[cfg(target_os = "linux")]
pub fn hostname() -> Option<String> {
    read_trimmed("/proc/sys/kernel/hostname").ok()
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).map_err(|e| format!("read {}: {}", path, e))
}

#[cfg(target_os = "macos")]
pub fn boot_id() -> Result<String, String> {
    let raw = sysctl_string(c"kern.bootsessionuuid").map_err(|e| format!("sysctl kern.bootsessionuuid: {}", e))?;
    lowercase_uuid(&raw).ok_or_else(|| format!("kern.bootsessionuuid {:?} is not a UUID", raw))
}

#[cfg(target_os = "macos")]
pub fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let s = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?.to_str().ok()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &std::ffi::CStr) -> std::io::Result<String> {
    let mut buf = [0u8; 128];
    let mut len = buf.len();
    let rc = unsafe { libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let s = std::ffi::CStr::from_bytes_until_nul(&buf[..len.min(buf.len())])
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(&buf[..len.min(buf.len())]).into_owned());
    Ok(s)
}

/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (any case, surrounding whitespace allowed)
/// → the same UUID in lowercase; anything else → `None`.
#[cfg(any(target_os = "macos", test))]
pub fn lowercase_uuid(raw: &str) -> Option<String> {
    let s = raw.trim();
    let groups: Vec<&str> = s.split('-').collect();
    let shape_ok = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()));
    shape_ok.then(|| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_uuid_is_lowercased_and_checked() {
        assert_eq!(
            lowercase_uuid("6F9619FF-8B86-4011-B42D-00C04FC96481\n").as_deref(),
            Some("6f9619ff-8b86-4011-b42d-00c04fc96481")
        );
        assert_eq!(lowercase_uuid("6f9619ff-8b86-4011-b42d-00c04fc96481").as_deref(), Some("6f9619ff-8b86-4011-b42d-00c04fc96481"));
        for bad in ["", "not-a-uuid", "6F9619FF8B864011B42D00C04FC96481", "6F9619FF-8B86-4011-B42D-00C04FC9648G", "6F9619FF-8B86-4011-B42D-00C04FC96481-00"] {
            assert_eq!(lowercase_uuid(bad), None, "{:?}", bad);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_boot_id_is_already_a_lowercase_uuid() {
        let id = boot_id().unwrap();
        assert_eq!(lowercase_uuid(&id).as_deref(), Some(id.as_str()));
    }
}
