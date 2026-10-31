//! Read-only vault client: decrypt `GET /api/vault` exactly as the desktop Keeper
//! does (remote-browser-keeper `src/vault.js`), check `secret_id`, never write.

use std::collections::HashMap;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const FORMAT_SHA256_V2: &str = "aesgcm-sha256-v2";
pub const FORMAT_PBKDF2_V2: &str = "aesgcm-pbkdf2-v2";
pub const FORMAT_V1: &str = "aesgcm-sha256-v1";
pub const PBKDF2_ITERATIONS: u32 = 210_000;
const SALT_BYTES: usize = 16;
const ID_DOMAIN: &[u8] = b"rbvault-id-v2";
const MIN_BODY: usize = 12 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Sha256V2,
    Pbkdf2V2,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self, VaultError> {
        match s {
            FORMAT_SHA256_V2 => Ok(Format::Sha256V2),
            FORMAT_PBKDF2_V2 => Ok(Format::Pbkdf2V2),
            // v1 blobs predate secret_id-v2; a headless Keeper is only paired with v2.
            FORMAT_V1 => Err(VaultError::Unsupported(FORMAT_V1.into())),
            other => Err(VaultError::Unsupported(sanitize(other))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Sha256V2 => FORMAT_SHA256_V2,
            Format::Pbkdf2V2 => FORMAT_PBKDF2_V2,
        }
    }
}

fn sanitize(s: &str) -> String {
    s.chars().take(40).filter(|c| c.is_ascii_graphic()).collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    Unsupported(String),
    /// The stored blob was written under another password (desktop `VaultKeyMismatch`).
    KeyMismatch,
    /// Too short, bad base64, GCM tag failure or a plaintext that is not the blob JSON.
    Corrupt(&'static str),
    /// `GET /api/vault` returned 401: the device token is no longer valid.
    Unauthorized,
    /// Any other transport/HTTP failure. Carries no response body.
    Http(String),
}

impl VaultError {
    /// Errors that mean the held key is wrong, so the daemon must wipe and re-unlock.
    pub fn locks(&self) -> bool {
        matches!(self, VaultError::KeyMismatch | VaultError::Corrupt(_) | VaultError::Unauthorized | VaultError::Unsupported(_))
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Unsupported(fmt_) => write!(f, "unsupported vault format {:?}", fmt_),
            VaultError::KeyMismatch => write!(f, "vault secret mismatch (password changed; re-unlock)"),
            VaultError::Corrupt(why) => write!(f, "vault does not decrypt: {}", why),
            VaultError::Unauthorized => write!(f, "vault GET 401: device token rejected"),
            VaultError::Http(why) => write!(f, "vault GET failed: {}", why),
        }
    }
}

impl std::error::Error for VaultError {}

/// Master key for `format`; for pbkdf2 the salt is the envelope's first 16 bytes.
/// Returns the master and the `iv‖ct‖tag` body.
fn open_envelope<'a>(
    format: Format,
    password: &SecretString,
    envelope: &'a [u8],
) -> Result<(Zeroizing<[u8; 32]>, &'a [u8]), VaultError> {
    let pw = password.expose_secret().as_bytes();
    let mut master = Zeroizing::new([0u8; 32]);
    match format {
        Format::Sha256V2 => {
            if envelope.len() < MIN_BODY {
                return Err(VaultError::Corrupt("ciphertext too short"));
            }
            master.copy_from_slice(&Sha256::digest(pw));
            Ok((master, envelope))
        }
        Format::Pbkdf2V2 => {
            if envelope.len() < SALT_BYTES + MIN_BODY {
                return Err(VaultError::Corrupt("ciphertext too short"));
            }
            let (salt, body) = envelope.split_at(SALT_BYTES);
            pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, PBKDF2_ITERATIONS, &mut master[..]);
            Ok((master, body))
        }
    }
}

/// `hex(SHA-256("rbvault-id-v2" ‖ master))`: the opaque, non-secret vault id.
pub fn secret_id_from_master(master: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(ID_DOMAIN);
    h.update(master);
    hex::encode(h.finalize())
}

/// Decrypt one envelope (base64) to its plaintext JSON bytes. When `secret_id` is
/// given it must match the one our password derives, before any decryption.
pub fn decrypt(
    format: Format,
    password: &SecretString,
    ciphertext_b64: &str,
    secret_id: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let envelope = Zeroizing::new(B64.decode(ciphertext_b64).map_err(|_| VaultError::Corrupt("ciphertext is not base64"))?);
    let (master, body) = open_envelope(format, password, &envelope)?;
    if let Some(expected) = secret_id {
        if !expected.is_empty() && secret_id_from_master(&master) != expected {
            return Err(VaultError::KeyMismatch);
        }
    }
    let (iv, rest) = body.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&master[..]).expect("32-byte key");
    let pt = cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: rest, aad: b"" })
        .map_err(|_| VaultError::Corrupt("AES-GCM authentication failed"))?;
    Ok(Zeroizing::new(pt))
}

/// One saved field. `value` is a secret; `Debug` shows only `auto`.
pub struct Entry {
    pub value: SecretString,
    pub auto: bool,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry").field("value", &"[REDACTED]").field("auto", &self.auto).finish()
    }
}

/// The decrypted vault, held in RAM only. Only live string-valued `fields` are kept;
/// cards and everything else in the blob are dropped (a headless Keeper fills fields
/// only).
#[derive(Default)]
pub struct Vault {
    pub version: u64,
    pub format: Option<Format>,
    pub fields: HashMap<String, Entry>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("version", &self.version)
            .field("format", &self.format)
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl Vault {
    /// Build from the decrypted blob JSON. Tombstones (`deleted`) and non-object or
    /// non-string entries are skipped, as the desktop's `isLive` / `getSaved` do.
    pub fn from_plaintext(version: u64, format: Format, plaintext: &[u8]) -> Result<Self, VaultError> {
        let blob: Zeroizing<String> = Zeroizing::new(
            String::from_utf8(plaintext.to_vec()).map_err(|_| VaultError::Corrupt("plaintext is not UTF-8"))?,
        );
        let mut v: Value = serde_json::from_str(&blob).map_err(|_| VaultError::Corrupt("plaintext is not JSON"))?;
        let mut fields = HashMap::new();
        if let Some(Value::Object(map)) = v.get_mut("fields") {
            for (k, e) in std::mem::take(map) {
                let Value::Object(mut e) = e else { continue };
                if e.get("deleted").map(truthy).unwrap_or(false) {
                    continue;
                }
                let auto = e.get("auto").map(truthy).unwrap_or(false);
                if let Some(Value::String(s)) = e.remove("value") {
                    fields.insert(k, Entry { value: SecretString::from(s), auto });
                }
            }
        }
        scrub(&mut v);
        Ok(Vault { version, format: Some(format), fields })
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// JS truthiness for the JSON values a blob may carry.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// Overwrite every string left in a parsed blob (cards etc.) before it drops.
fn scrub(v: &mut Value) {
    use zeroize::Zeroize;
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
}

/// The parts of a `GET /api/vault` 200 body the daemon needs.
pub struct VaultResponse {
    pub version: u64,
    pub secret_id: Option<String>,
    pub format: Option<String>,
    pub ciphertext: String,
}

impl VaultResponse {
    pub fn parse(body: &[u8]) -> Result<Self, VaultError> {
        let v: Value = serde_json::from_slice(body).map_err(|_| VaultError::Http("body is not JSON".into()))?;
        let version = match &v["version"] {
            Value::Number(n) => n.as_u64().unwrap_or(0),
            Value::String(s) => s.parse().unwrap_or(0),
            _ => 0,
        };
        let opt = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
        Ok(VaultResponse {
            version,
            secret_id: opt("secret_id"),
            format: opt("format"),
            ciphertext: v.get("ciphertext").and_then(Value::as_str).unwrap_or("").to_string(),
        })
    }

    /// Desktop `pullVault`: format = body.format || our key's format; check
    /// secret_id when present; decrypt.
    pub fn open(&self, key_format: Format, password: &SecretString) -> Result<Vault, VaultError> {
        let format = match &self.format {
            Some(f) => Format::parse(f)?,
            None => key_format,
        };
        let pt = decrypt(format, password, &self.ciphertext, self.secret_id.as_deref())?;
        Vault::from_plaintext(self.version, format, &pt)
    }
}

/// `GET {base}/api/vault` with the device token. 404 = no vault yet (version 0).
pub async fn pull(
    client: &reqwest::Client,
    base: &url::Url,
    token: &SecretString,
    key_format: Format,
    password: &SecretString,
) -> Result<Vault, VaultError> {
    let url = base.join("api/vault").map_err(|_| VaultError::Http("bad server URL".into()))?;
    let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
        .map_err(|_| VaultError::Http("token is not a valid header value".into()))?;
    auth.set_sensitive(true);
    let res = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .map_err(|e| VaultError::Http(e.without_url().to_string()))?;
    match res.status().as_u16() {
        404 => return Ok(Vault { version: 0, format: Some(key_format), fields: HashMap::new() }),
        401 => return Err(VaultError::Unauthorized),
        s if !(200..300).contains(&s) => return Err(VaultError::Http(format!("status {}", s))),
        _ => {}
    }
    let body = Zeroizing::new(res.bytes().await.map_err(|e| VaultError::Http(e.without_url().to_string()))?.to_vec());
    VaultResponse::parse(&body)?.open(key_format, password)
}

/// Test/fixture helper: encrypt a blob the way `encryptVault` does. Returns
/// `(ciphertext_b64, secret_id)`. Used to generate fixtures for both formats.
pub fn encrypt_for_tests(format: Format, password: &str, salt: &[u8; 16], iv: &[u8; 12], plaintext: &[u8]) -> (String, String) {
    let pw = SecretString::from(password.to_string());
    let mut envelope = Vec::new();
    let master = match format {
        Format::Sha256V2 => {
            let mut m = Zeroizing::new([0u8; 32]);
            m.copy_from_slice(&Sha256::digest(pw.expose_secret().as_bytes()));
            m
        }
        Format::Pbkdf2V2 => {
            envelope.extend_from_slice(salt);
            let mut m = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(pw.expose_secret().as_bytes(), salt, PBKDF2_ITERATIONS, &mut m[..]);
            m
        }
    };
    let cipher = Aes256Gcm::new_from_slice(&master[..]).unwrap();
    let ct = cipher.encrypt(Nonce::from_slice(iv), plaintext).unwrap();
    envelope.extend_from_slice(iv);
    envelope.extend_from_slice(&ct);
    (B64.encode(envelope), secret_id_from_master(&master))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = r#"{"schema":1,"fields":{
        "bank|bank.example|#user":{"value":"fixture-user","auto":true,"updated_at":"2026-10-01T00:00:00Z"},
        "bank|bank.example|#pass":{"value":"fixture-pass","auto":true},
        "bank|bank.example|#memo":{"value":"fixture-memo","auto":false},
        "bank|bank.example|#gone":{"deleted":true,"updated_at":"2026-10-02T00:00:00Z"},
        "bank|bank.example|#num":{"value":7,"auto":true},
        "bank|bank.example|#bare":"bare-string"},
      "cards":{"c1":{"number":"4111111111111111"}},"cardsMeta":{},"headless_keepers":[]}"#;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    fn fixture(format: Format) -> (String, String) {
        encrypt_for_tests(format, "fixture-password", &[7u8; 16], &[9u8; 12], BLOB.as_bytes())
    }

    #[test]
    fn sha256_v2_fixture_decrypts() {
        let (ct, sid) = fixture(Format::Sha256V2);
        let body = format!(r#"{{"version":5,"secret_id":"{}","format":"aesgcm-sha256-v2","ciphertext":"{}"}}"#, sid, ct);
        let v = VaultResponse::parse(body.as_bytes()).unwrap().open(Format::Pbkdf2V2, &pw("fixture-password")).unwrap();
        assert_eq!(v.version, 5);
        assert_eq!(v.format, Some(Format::Sha256V2), "the body's format wins over the key's");
        assert_eq!(v.len(), 3, "tombstones, non-string values and bare strings are dropped");
        assert_eq!(v.fields["bank|bank.example|#user"].value.expose_secret(), "fixture-user");
        assert!(v.fields["bank|bank.example|#user"].auto);
        assert!(!v.fields["bank|bank.example|#memo"].auto);
        assert!(!v.fields.contains_key("bank|bank.example|#gone"));
    }

    #[test]
    fn pbkdf2_v2_fixture_decrypts_with_the_envelope_salt() {
        let (ct, sid) = fixture(Format::Pbkdf2V2);
        let raw = B64.decode(&ct).unwrap();
        assert_eq!(&raw[..16], &[7u8; 16], "salt is the envelope prefix");
        // No body.format: falls back to the key's format.
        let body = format!(r#"{{"version":"2","secret_id":"{}","ciphertext":"{}"}}"#, sid, ct);
        let v = VaultResponse::parse(body.as_bytes()).unwrap().open(Format::Pbkdf2V2, &pw("fixture-password")).unwrap();
        assert_eq!(v.version, 2);
        assert_eq!(v.fields["bank|bank.example|#pass"].value.expose_secret(), "fixture-pass");
    }

    #[test]
    fn secret_id_matches_the_desktop_derivation() {
        // secret_id = hex(sha256("rbvault-id-v2" || sha256(pw))) for sha256-v2.
        let master: [u8; 32] = Sha256::digest(b"fixture-password").into();
        let mut h = Sha256::new();
        h.update(b"rbvault-id-v2");
        h.update(master);
        assert_eq!(fixture(Format::Sha256V2).1, hex::encode(h.finalize()));
    }

    #[test]
    fn a_secret_id_mismatch_is_a_key_mismatch() {
        for f in [Format::Sha256V2, Format::Pbkdf2V2] {
            let (ct, sid) = fixture(f);
            assert_eq!(decrypt(f, &pw("other-password"), &ct, Some(&sid)).unwrap_err(), VaultError::KeyMismatch);
            let wrong = "0".repeat(64);
            assert_eq!(decrypt(f, &pw("fixture-password"), &ct, Some(&wrong)).unwrap_err(), VaultError::KeyMismatch);
            assert!(VaultError::KeyMismatch.locks());
        }
    }

    #[test]
    fn without_secret_id_a_wrong_password_fails_gcm() {
        let (ct, _) = fixture(Format::Sha256V2);
        let e = decrypt(Format::Sha256V2, &pw("other-password"), &ct, None).unwrap_err();
        assert!(matches!(e, VaultError::Corrupt(_)));
        assert!(e.locks());
    }

    #[test]
    fn short_and_tampered_envelopes_fail() {
        assert!(matches!(decrypt(Format::Sha256V2, &pw("x"), &B64.encode([0u8; 27]), None), Err(VaultError::Corrupt(_))));
        assert!(matches!(decrypt(Format::Pbkdf2V2, &pw("x"), &B64.encode([0u8; 43]), None), Err(VaultError::Corrupt(_))));
        let (ct, sid) = fixture(Format::Sha256V2);
        let mut raw = B64.decode(ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(matches!(decrypt(Format::Sha256V2, &pw("fixture-password"), &B64.encode(raw), Some(&sid)), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn v1_and_unknown_formats_are_refused() {
        assert_eq!(Format::parse("aesgcm-sha256-v1"), Err(VaultError::Unsupported("aesgcm-sha256-v1".into())));
        assert!(Format::parse("rot13").is_err());
        let (ct, sid) = fixture(Format::Sha256V2);
        let body = format!(r#"{{"version":1,"secret_id":"{}","format":"aesgcm-sha256-v1","ciphertext":"{}"}}"#, sid, ct);
        assert!(VaultResponse::parse(body.as_bytes()).unwrap().open(Format::Sha256V2, &pw("fixture-password")).is_err());
    }

    #[test]
    fn debug_shows_no_values() {
        let (ct, _) = fixture(Format::Sha256V2);
        let pt = decrypt(Format::Sha256V2, &pw("fixture-password"), &ct, None).unwrap();
        let v = Vault::from_plaintext(1, Format::Sha256V2, &pt).unwrap();
        let dbg = format!("{:?} {:?}", v, v.fields.values().collect::<Vec<_>>());
        assert!(!dbg.contains("fixture-"), "{}", dbg);
    }
}
