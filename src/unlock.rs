//! The unlock exchange (rbkeeper-unlock-v1 §3–§5): the signed `unlock_request`,
//! the comparison code, and opening the HPKE-sealed answer with the ephemeral key.

use std::fmt;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, Serializable};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::vault::Format;

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as KemTrait>::PrivateKey;
type PublicKey = <Kem as KemTrait>::PublicKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

pub const INFO_PREFIX: &str = "rbkeeper-unlock-v1|";

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError {
    /// A signed field is not printable ASCII (§2 keeps signing bytes ASCII-only).
    BadField(&'static str),
    /// The answer is not a well-formed `unlock_response`.
    Malformed(&'static str),
    /// The answer names a different request than our `unlock_pending`.
    WrongRequest,
    /// The ephemeral key was already used (or wiped).
    KeyGone,
    /// HPKE open failed: wrong key, info or aad, or a tampered ciphertext.
    OpenFailed,
    /// The plaintext opened but is not a v1 payload we can use.
    BadPayload(&'static str),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnlockError::BadField(n) => write!(f, "field {} is not printable ASCII", n),
            UnlockError::Malformed(why) => write!(f, "malformed unlock_response: {}", why),
            UnlockError::WrongRequest => write!(f, "unlock_response for another request_id"),
            UnlockError::KeyGone => write!(f, "ephemeral key already used"),
            UnlockError::OpenFailed => write!(f, "HPKE open failed"),
            UnlockError::BadPayload(why) => write!(f, "unusable unlock payload: {}", why),
        }
    }
}

impl std::error::Error for UnlockError {}

fn printable_ascii(name: &'static str, s: &str) -> Result<(), UnlockError> {
    if s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        Ok(())
    } else {
        Err(UnlockError::BadField(name))
    }
}

/// The fields of one `unlock_request` (everything but `sig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFields {
    pub headless_id: String,
    pub boot_id: String,
    pub eph_pub: String,
    pub ts: i64,
    pub nonce: String,
}

impl RequestFields {
    fn object(&self) -> Result<Map<String, Value>, UnlockError> {
        printable_ascii("headless_id", &self.headless_id)?;
        printable_ascii("boot_id", &self.boot_id)?;
        printable_ascii("eph_pub", &self.eph_pub)?;
        printable_ascii("nonce", &self.nonce)?;
        // serde_json's Map is a BTreeMap here (no `preserve_order`), so keys serialise
        // sorted; with ASCII-only strings and an integer ts the compact output is the
        // JCS form of §2.
        let mut m = Map::new();
        m.insert("type".into(), Value::from("unlock_request"));
        m.insert("headless_id".into(), Value::from(self.headless_id.clone()));
        m.insert("boot_id".into(), Value::from(self.boot_id.clone()));
        m.insert("eph_pub".into(), Value::from(self.eph_pub.clone()));
        m.insert("ts".into(), Value::from(self.ts));
        m.insert("nonce".into(), Value::from(self.nonce.clone()));
        Ok(m)
    }

    /// The exact bytes the identity key signs (§3).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, UnlockError> {
        Ok(serde_json::to_vec(&Value::Object(self.object()?)).expect("map serialises"))
    }

    /// The seven-field frame sent as the first message on the headless socket.
    pub fn signed_frame(&self, identity: &Identity) -> Result<String, UnlockError> {
        let sig = identity.sign(&self.signing_bytes()?);
        let mut m = self.object()?;
        m.insert("sig".into(), Value::from(B64.encode(sig)));
        Ok(serde_json::to_string(&Value::Object(m)).expect("map serialises"))
    }
}

/// A fresh 16-byte nonce, standard base64.
pub fn fresh_nonce() -> String {
    let mut n = [0u8; 16];
    OsRng.fill_bytes(&mut n);
    B64.encode(n)
}

/// `upper_hex(SHA-256(eph_pub_raw ‖ ascii(boot_id))[:4])` as `XXXX-XXXX` (§5).
pub fn comparison_code(eph_pub_raw: &[u8], boot_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(eph_pub_raw);
    h.update(boot_id.as_bytes());
    let d = hex::encode_upper(&h.finalize()[..4]);
    format!("{}-{}", &d[..4], &d[4..])
}

/// `"rbkeeper-unlock-v1|" + headless_id + "|" + boot_id` (§5).
pub fn hpke_info(headless_id: &str, boot_id: &str) -> String {
    format!("{}{}|{}", INFO_PREFIX, headless_id, boot_id)
}

/// The per-boot X25519 key (`EK`). The private half is RAM-only and is consumed by
/// the first `open`; `wipe` drops it early. hpke's X25519 private key zeroizes on drop.
pub struct EphemeralKey {
    sk: Option<PrivateKey>,
    pk: PublicKey,
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKey")
            .field("eph_pub", &self.public_b64())
            .field("has_private", &self.sk.is_some())
            .finish()
    }
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair(&mut OsRng);
        EphemeralKey { sk: Some(sk), pk }
    }

    /// Deterministic derivation (RFC 9180 DeriveKeyPair); tests use the vector IKM.
    pub fn from_ikm(ikm: &[u8]) -> Self {
        let (sk, pk) = Kem::derive_keypair(ikm);
        EphemeralKey { sk: Some(sk), pk }
    }

    pub fn public_raw(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.public_raw())
    }

    pub fn is_spent(&self) -> bool {
        self.sk.is_none()
    }

    pub fn wipe(&mut self) {
        self.sk = None;
    }

    /// Open an `unlock_response` sealed to this key. The private key is taken out
    /// first, so it is dropped (zeroized) whether or not the open succeeds: a
    /// response that fails to open means this request is over anyway.
    pub fn open(
        &mut self,
        info: &[u8],
        aad: &[u8],
        enc_b64: &str,
        ciphertext_b64: &str,
    ) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        let sk = self.sk.take().ok_or(UnlockError::KeyGone)?;
        let enc = B64.decode(enc_b64).map_err(|_| UnlockError::Malformed("enc is not base64"))?;
        let ct = B64
            .decode(ciphertext_b64)
            .map_err(|_| UnlockError::Malformed("ciphertext is not base64"))?;
        let encapped = EncappedKey::from_bytes(&enc).map_err(|_| UnlockError::Malformed("enc is not a key"))?;
        let pt = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            info,
            &ct,
            aad,
        )
        .map_err(|_| UnlockError::OpenFailed)?;
        crate::hardening::lock_in_ram(&pt);
        // `sk` (x25519-dalek StaticSecret, zeroize-on-drop via the feature named in
        // Cargo.toml) is wiped as it goes out of scope here, on success and on error.
        Ok(Zeroizing::new(pt))
    }
}

// Build-time guard: the ephemeral key wipes itself only while x25519-dalek's
// `zeroize` feature is on (see Cargo.toml); that feature is what derives both
// `Zeroize` and the wiping `Drop`. Losing it must fail the build.
const _: () = {
    fn zeroizable<T: zeroize::Zeroize>() {}
    let _ = zeroizable::<x25519_dalek::StaticSecret>;
    assert!(std::mem::needs_drop::<x25519_dalek::StaticSecret>());
};

/// Test helper: an `EphemeralKey` from a raw private key (the vectors give one).
pub fn ephemeral_from_sk_bytes(sk: &[u8]) -> Option<EphemeralKey> {
    let sk = PrivateKey::from_bytes(sk).ok()?;
    let pk = Kem::sk_to_pk(&sk);
    Some(EphemeralKey { sk: Some(sk), pk })
}

/// What a Keeper's approval carries (§5 step 3). Secrets stay in `SecretString`,
/// whose `Debug` is redacted and which zeroizes on drop.
#[derive(Debug)]
pub struct UnlockPayload {
    pub device_token: SecretString,
    pub issued_at: i64,
    pub vault_format: Format,
    pub vault_password: SecretString,
}

#[derive(Deserialize)]
struct RawVault {
    format: String,
    password: SecretString,
}

#[derive(Deserialize)]
struct RawPayload {
    v: i64,
    device_token: SecretString,
    #[serde(default)]
    issued_at: i64,
    vault: RawVault,
}

impl UnlockPayload {
    pub fn parse(plaintext: &[u8]) -> Result<Self, UnlockError> {
        // serde's error text can quote input, so it is dropped, never logged.
        let raw: RawPayload = serde_json::from_slice(plaintext).map_err(|_| UnlockError::BadPayload("not the v1 JSON shape"))?;
        if raw.v != 1 {
            return Err(UnlockError::BadPayload("v is not 1"));
        }
        if raw.device_token.expose_secret().is_empty() {
            return Err(UnlockError::BadPayload("empty device_token"));
        }
        if raw.vault.password.expose_secret().is_empty() {
            return Err(UnlockError::BadPayload("empty vault password"));
        }
        let vault_format = Format::parse(&raw.vault.format).map_err(|_| UnlockError::BadPayload("unsupported vault format"))?;
        crate::hardening::lock_in_ram(raw.device_token.expose_secret().as_bytes());
        crate::hardening::lock_in_ram(raw.vault.password.expose_secret().as_bytes());
        Ok(UnlockPayload {
            device_token: raw.device_token,
            issued_at: raw.issued_at,
            vault_format,
            vault_password: raw.vault.password,
        })
    }
}

/// The two answers the headless socket can carry before it closes.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Approved { enc: String, ciphertext: String },
    Denied,
    /// `unlock_resolved` with `timeout` / `cancelled` (or any other status).
    Resolved(String),
}

/// Parse a frame on the headless socket after `unlock_pending`, checking that it
/// names our request (§8 step 1).
pub fn parse_answer(text: &str, request_id: &str) -> Result<Option<Answer>, UnlockError> {
    let v: Value = serde_json::from_str(text).map_err(|_| UnlockError::Malformed("not JSON"))?;
    let ty = v.get("type").and_then(Value::as_str).unwrap_or("");
    if ty != "unlock_response" && ty != "unlock_resolved" {
        return Ok(None);
    }
    if v.get("request_id").and_then(Value::as_str) != Some(request_id) {
        return Err(UnlockError::WrongRequest);
    }
    if ty == "unlock_resolved" {
        let status = v.get("status").and_then(Value::as_str).unwrap_or("").to_string();
        return Ok(Some(Answer::Resolved(status)));
    }
    if v.get("denied").and_then(Value::as_bool) == Some(true) {
        return Ok(Some(Answer::Denied));
    }
    let enc = v.get("enc").and_then(Value::as_str).ok_or(UnlockError::Malformed("no enc"))?;
    let ct = v.get("ciphertext").and_then(Value::as_str).ok_or(UnlockError::Malformed("no ciphertext"))?;
    Ok(Some(Answer::Approved { enc: enc.to_string(), ciphertext: ct.to_string() }))
}

/// Parse the server's `unlock_pending` frame.
pub fn parse_pending(text: &str) -> Option<String> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("unlock_pending") {
        return None;
    }
    let rid = v.get("request_id").and_then(Value::as_str)?;
    if rid.is_empty() || rid.len() > 256 {
        return None;
    }
    Some(rid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/rbkeeper-unlock-v1-vectors.json")).unwrap()
    }

    fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
        let mut cur = v;
        for p in path {
            cur = &cur[*p];
        }
        cur.as_str().unwrap_or_else(|| panic!("missing {:?}", path))
    }

    fn identity() -> Identity {
        let v = vectors();
        Identity::from_seed(&hex::decode(s(&v, &["identity", "ed25519_seed_hex"])).unwrap().try_into().unwrap())
    }

    fn vector_fields() -> RequestFields {
        let v = vectors();
        let f = &v["unlock_request"]["frame"];
        RequestFields {
            headless_id: s(f, &["headless_id"]).into(),
            boot_id: s(f, &["boot_id"]).into(),
            eph_pub: s(f, &["eph_pub"]).into(),
            ts: f["ts"].as_i64().unwrap(),
            nonce: s(f, &["nonce"]).into(),
        }
    }

    #[test]
    fn signing_bytes_match_part_1_canonicalisation() {
        let v = vectors();
        let bytes = vector_fields().signing_bytes().unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), s(&v, &["unlock_request", "signing_bytes_utf8"]));
        assert_eq!(hex::encode(&bytes), s(&v, &["unlock_request", "signing_bytes_hex"]));
    }

    #[test]
    fn signed_frame_matches_the_vector_and_verifies() {
        let v = vectors();
        let frame: Value = serde_json::from_str(&vector_fields().signed_frame(&identity()).unwrap()).unwrap();
        assert_eq!(frame, v["unlock_request"]["frame"]);
        assert_eq!(frame.as_object().unwrap().len(), 7);
        assert_eq!(frame["sig"], v["unlock_request"]["sig"]);

        let pk: [u8; 32] = B64.decode(s(&v, &["identity", "ed25519_pub"])).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let sig: [u8; 64] = B64.decode(s(&frame, &["sig"])).unwrap().try_into().unwrap();
        vk.verify(&vector_fields().signing_bytes().unwrap(), &Signature::from_bytes(&sig)).unwrap();
    }

    #[test]
    fn non_ascii_and_control_characters_are_refused() {
        let mut f = vector_fields();
        f.boot_id = "6f9619ff\u{e9}".into();
        assert_eq!(f.signing_bytes(), Err(UnlockError::BadField("boot_id")));
        let mut f = vector_fields();
        f.nonce = "a\nb".into();
        assert_eq!(f.signing_bytes(), Err(UnlockError::BadField("nonce")));
    }

    #[test]
    fn comparison_code_and_info_match_the_vectors() {
        let v = vectors();
        let f = vector_fields();
        let raw = B64.decode(&f.eph_pub).unwrap();
        assert_eq!(comparison_code(&raw, &f.boot_id), s(&v, &["unlock_request", "comparison_code"]));
        assert_eq!(hpke_info(&f.headless_id, &f.boot_id), s(&v, &["hpke", "info_utf8"]));
    }

    #[test]
    fn ikm_and_sk_both_give_the_vector_public_key() {
        let v = vectors();
        let from_ikm = EphemeralKey::from_ikm(&hex::decode(s(&v, &["hpke", "recipient_ikm_hex"])).unwrap());
        assert_eq!(from_ikm.public_b64(), s(&v, &["hpke", "recipient_pk"]));
        let from_sk = ephemeral_from_sk_bytes(&hex::decode(s(&v, &["hpke", "recipient_sk_hex"])).unwrap()).unwrap();
        assert_eq!(from_sk.public_b64(), s(&v, &["hpke", "recipient_pk"]));
    }

    #[test]
    fn hpke_open_of_the_shared_vector_then_the_key_is_gone() {
        let v = vectors();
        let mut ek = EphemeralKey::from_ikm(&hex::decode(s(&v, &["hpke", "recipient_ikm_hex"])).unwrap());
        let resp = serde_json::to_string(&v["hpke"]["unlock_response"]).unwrap();
        let rid = s(&v, &["hpke", "aad_utf8"]);
        let Some(Answer::Approved { enc, ciphertext }) = parse_answer(&resp, rid).unwrap() else {
            panic!("vector response is an approval");
        };
        let info = s(&v, &["hpke", "info_utf8"]);
        let pt = ek.open(info.as_bytes(), rid.as_bytes(), &enc, &ciphertext).unwrap();
        assert_eq!(std::str::from_utf8(&pt).unwrap(), s(&v, &["hpke", "plaintext_utf8"]));
        assert!(ek.is_spent(), "EK must be zeroized after opening");
        assert_eq!(ek.open(info.as_bytes(), rid.as_bytes(), &enc, &ciphertext), Err(UnlockError::KeyGone));

        let payload = UnlockPayload::parse(&pt).unwrap();
        assert_eq!(payload.vault_format, Format::Pbkdf2V2);
        assert_eq!(payload.issued_at, 1793000042);
        let dbg = format!("{:?}", payload);
        assert!(!dbg.contains("TEST-VECTOR-ONLY"), "Debug must not show secrets: {}", dbg);
    }

    #[test]
    fn hpke_open_fails_with_the_wrong_aad_or_info() {
        let v = vectors();
        let ikm = hex::decode(s(&v, &["hpke", "recipient_ikm_hex"])).unwrap();
        let enc = s(&v, &["hpke", "enc"]);
        let ct = s(&v, &["hpke", "ciphertext"]);
        let info = s(&v, &["hpke", "info_utf8"]);
        let mut ek = EphemeralKey::from_ikm(&ikm);
        assert_eq!(ek.open(info.as_bytes(), b"req_other", enc, ct), Err(UnlockError::OpenFailed));
        assert!(ek.is_spent(), "a failed open also spends the key");
        let mut ek = EphemeralKey::from_ikm(&ikm);
        let other_boot = hpke_info(s(&v, &["identity", "headless_id"]), "00000000-0000-0000-0000-000000000000");
        assert_eq!(ek.open(other_boot.as_bytes(), s(&v, &["hpke", "aad_utf8"]).as_bytes(), enc, ct), Err(UnlockError::OpenFailed));
    }

    #[test]
    fn answers_for_another_request_are_refused() {
        let deny = r#"{"type":"unlock_response","request_id":"req_b","denied":true}"#;
        assert_eq!(parse_answer(deny, "req_a"), Err(UnlockError::WrongRequest));
        assert_eq!(parse_answer(deny, "req_b"), Ok(Some(Answer::Denied)));
        let to = r#"{"type":"unlock_resolved","request_id":"req_a","status":"timeout"}"#;
        assert_eq!(parse_answer(to, "req_a"), Ok(Some(Answer::Resolved("timeout".into()))));
        assert_eq!(parse_answer(r#"{"type":"ping"}"#, "req_a"), Ok(None));
        assert_eq!(parse_pending(r#"{"type":"unlock_pending","request_id":"req_x"}"#), Some("req_x".into()));
        assert_eq!(parse_pending(r#"{"type":"unlock_pending"}"#), None);
    }

    #[test]
    fn payload_validation() {
        let ok = br#"{"device_token":"t","issued_at":1,"v":1,"vault":{"format":"aesgcm-sha256-v2","password":"p"}}"#;
        assert_eq!(UnlockPayload::parse(ok).unwrap().vault_format, Format::Sha256V2);
        for bad in [
            &br#"{"device_token":"t","v":2,"vault":{"format":"aesgcm-sha256-v2","password":"p"}}"#[..],
            br#"{"device_token":"","v":1,"vault":{"format":"aesgcm-sha256-v2","password":"p"}}"#,
            br#"{"device_token":"t","v":1,"vault":{"format":"aesgcm-sha256-v1","password":"p"}}"#,
            br#"{"device_token":"t","v":1,"vault":{"format":"aesgcm-sha256-v2","password":""}}"#,
            br#"not json"#,
        ] {
            assert!(UnlockPayload::parse(bad).is_err());
        }
    }
}
