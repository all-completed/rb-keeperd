//! The daemon's long-lived Ed25519 identity (`IK`, rbkeeper-unlock-v1 §3).
//!
//! The 32-byte seed lives in one root-only file. It is created once by
//! `rbkeeperd enroll` and only read by `rbkeeperd run`. The seed never leaves this
//! module: callers get the public key, the derived ids and signatures.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(not(target_os = "macos"))]
pub const DEFAULT_IDENTITY_PATH: &str = "/var/lib/rbkeeperd/identity.key";
#[cfg(target_os = "macos")]
pub const DEFAULT_IDENTITY_PATH: &str = "/Library/Application Support/rbkeeperd/identity.key";
const SEED_LEN: usize = 32;

#[derive(Debug)]
pub enum IdentityError {
    Io(PathBuf, io::Error),
    /// The file exists but is not exactly what `enroll` writes.
    Unsafe(PathBuf, String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Io(p, e) => write!(f, "{}: {}", p.display(), e),
            IdentityError::Unsafe(p, why) => write!(f, "{}: refusing identity file: {}", p.display(), why),
        }
    }
}

impl std::error::Error for IdentityError {}

/// The identity key. `SigningKey` zeroizes its seed on drop (ed25519-dalek `zeroize`).
pub struct Identity {
    key: SigningKey,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The public half only; the seed is never formatted.
        f.debug_struct("Identity").field("headless_id", &self.headless_id()).finish()
    }
}

impl Identity {
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Identity { key: SigningKey::from_bytes(seed) }
    }

    pub fn public_raw(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Standard padded base64, the `ed25519_pub` the Keeper pins (§2).
    pub fn public_b64(&self) -> String {
        B64.encode(self.public_raw())
    }

    pub fn headless_id(&self) -> String {
        headless_id(&self.public_raw())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_raw())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// Load the identity, refusing anything `create` would not have produced:
    /// not a regular file, a mode other than 0600, another owner, or a wrong size.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let io_err = |e| IdentityError::Io(path.to_path_buf(), e);
        let meta = fs::symlink_metadata(path).map_err(io_err)?;
        if !meta.file_type().is_file() {
            return Err(IdentityError::Unsafe(path.into(), "not a regular file".into()));
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode != 0o600 {
            return Err(IdentityError::Unsafe(path.into(), format!("mode {:o}, expected 600", mode)));
        }
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(IdentityError::Unsafe(
                path.into(),
                format!("owned by uid {}, expected uid {}", meta.uid(), euid),
            ));
        }
        if meta.len() != SEED_LEN as u64 {
            return Err(IdentityError::Unsafe(path.into(), format!("{} bytes, expected {}", meta.len(), SEED_LEN)));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(io_err)?;
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        file.read_exact(&mut seed[..]).map_err(io_err)?;
        Ok(Identity::from_seed(&seed))
    }

    /// Create a fresh identity at `path`. Never overwrites: `O_EXCL` fails if the
    /// file exists. The directory is created 0700 and the file 0600.
    pub fn create(path: &Path) -> Result<Self, IdentityError> {
        let io_err = |e| IdentityError::Io(path.to_path_buf(), e);
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() && !dir.exists() {
                DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(io_err)?;
            }
        }
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        OsRng.fill_bytes(&mut seed[..]);
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(io_err)?;
        // The umask can only remove bits, but set the mode explicitly anyway.
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io_err)?;
        file.write_all(&seed[..]).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        if let Some(dir) = path.parent() {
            if let Ok(d) = File::open(if dir.as_os_str().is_empty() { Path::new(".") } else { dir }) {
                let _ = d.sync_all();
            }
        }
        Ok(Identity::from_seed(&seed))
    }

    /// `enroll`: create the identity once; later calls load and reprint it.
    /// Returns the identity and whether it was created now.
    pub fn enroll(path: &Path) -> Result<(Self, bool), IdentityError> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok((Identity::load(path)?, false)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((Identity::create(path)?, true)),
            Err(e) => Err(IdentityError::Io(path.into(), e)),
        }
    }
}

/// `"hk1_" + lowerhex(SHA-256(pub))[:32]` (§3).
pub fn headless_id(public_raw: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_raw);
    format!("hk1_{}", &hex::encode(digest)[..32])
}

/// `"rbk1-" + BASE32(SHA-256(pub))[:12]` in groups of four (§3).
pub fn fingerprint(public_raw: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_raw);
    let b32 = data_encoding::BASE32.encode(&digest);
    let head = &b32[..12];
    format!("rbk1-{}-{}-{}", &head[0..4], &head[4..8], &head[8..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/vectors/rbkeeper-unlock-v1-vectors.json")).unwrap()
    }

    fn seed() -> [u8; 32] {
        let v = vectors();
        let hex_seed = v["identity"]["ed25519_seed_hex"].as_str().unwrap();
        hex::decode(hex_seed).unwrap().try_into().unwrap()
    }

    #[test]
    fn derivations_match_the_vectors() {
        let v = vectors();
        let id = Identity::from_seed(&seed());
        assert_eq!(id.public_b64(), v["identity"]["ed25519_pub"].as_str().unwrap());
        assert_eq!(id.headless_id(), v["identity"]["headless_id"].as_str().unwrap());
        assert_eq!(id.fingerprint(), v["identity"]["fingerprint"].as_str().unwrap());
    }

    #[test]
    fn debug_never_shows_the_seed() {
        let id = Identity::from_seed(&seed());
        let dbg = format!("{:?}", id);
        assert!(!dbg.contains(&hex::encode(seed())));
        assert!(dbg.contains("hk1_"));
    }

    #[test]
    fn create_writes_a_0600_file_owned_by_us_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("identity.key");
        let (a, created) = Identity::enroll(&path).unwrap();
        assert!(created);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        assert_eq!(meta.len(), 32);
        let dmeta = fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(dmeta.permissions().mode() & 0o777, 0o700);

        // Idempotent: a second enroll loads the same key.
        let (b, created) = Identity::enroll(&path).unwrap();
        assert!(!created);
        assert_eq!(a.public_raw(), b.public_raw());
        assert!(Identity::create(&path).is_err(), "O_EXCL must refuse to overwrite");
    }

    #[test]
    fn load_refuses_loose_modes_and_wrong_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        Identity::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Identity::load(&path), Err(IdentityError::Unsafe(..))));

        let short = dir.path().join("short.key");
        fs::write(&short, [0u8; 31]).unwrap();
        fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(Identity::load(&short), Err(IdentityError::Unsafe(..))));

        let link = dir.path().join("link.key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(Identity::load(&link), Err(IdentityError::Unsafe(..))));
    }
}
