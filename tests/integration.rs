//! `daemon::run` end to end against a mock server: the headless unlock socket, the
//! keeper socket and `GET /api/vault` on one loopback port. Every test also checks
//! the captured log for the secrets it handed the daemon (issue #83 "no secret in
//! logs").

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeS, Serializable};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use url::Url;

use rb_keeperd::daemon::{self, Config};
use rb_keeperd::identity::Identity;
use rb_keeperd::unlock::{hpke_info, RequestFields};
use rb_keeperd::vault::{encrypt_for_tests, Format};

// Distinctive fixture secrets: none of them may ever appear in the log.
const TOKEN: &str = "fixture-device-token-7Qx9";
const PASSWORD: &str = "fixture-vault-password-Kz3";
const USER_VALUE: &str = "fixture-user-value-Mm1";
const PASS_VALUE: &str = "fixture-pass-value-Pp2";
const MEMO_VALUE: &str = "fixture-memo-value-Nn3";
const OTP_VALUE: &str = "fixture-otp-value-Oo4";
const BOOT: &str = "6f1d2c3b-0000-4000-8000-00000000b007";

// An upper bound for things that must happen; a pass never waits it out. Generous
// because a 210k-round PBKDF2 on a loaded CI node took over 10 s.
const WAIT: Duration = Duration::from_secs(60);
const QUIET: Duration = Duration::from_millis(400);

// ───────────────────────────── captured log ─────────────────────────────

struct Capture;

fn lines() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

/// Keeps what the daemon's journald logger would write at its most verbose level
/// (`RBKEEPERD_LOG=debug`), through the same filter.
impl log::Log for Capture {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        rb_keeperd::logging::allowed(m, log::LevelFilter::Debug)
    }
    fn log(&self, r: &log::Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        lines().lock().unwrap().push(format!("{} {} {}", r.level(), r.target(), r.args()));
    }
    fn flush(&self) {}
}

fn capture_logs() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        log::set_boxed_logger(Box::new(Capture)).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    });
}

fn log_text() -> String {
    lines().lock().unwrap().join("\n")
}

/// Tests share one logger, so this checks the whole binary's log so far.
fn assert_no_secret_logged(extra: &[&str]) {
    let all = log_text();
    for s in [TOKEN, PASSWORD, USER_VALUE, PASS_VALUE, MEMO_VALUE, OTP_VALUE].iter().chain(extra) {
        let hits: Vec<String> = all.lines().filter(|l| l.contains(s)).map(|l| l.split(' ').take(2).collect::<Vec<_>>().join(" ")).collect();
        assert!(hits.is_empty(), "a fixture secret reached the log via {:?}", hits);
    }
}

// ───────────────────────────── mock server ─────────────────────────────

type Sock = WebSocketStream<TcpStream>;

struct VaultState {
    status: u16,
    body: String,
    hits: usize,
    auth: Vec<String>,
}

struct Mock {
    port: u16,
    headless: mpsc::UnboundedReceiver<(Value, Sock)>,
    keeper: mpsc::UnboundedReceiver<(Option<String>, Sock)>,
    vault: Arc<Mutex<VaultState>>,
    keeper_status: Arc<Mutex<u16>>,
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 8192];
    for _ in 0..500 {
        let n = stream.peek(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(i) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buf[..i]).into_owned());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

async fn serve_vault(mut stream: TcpStream, head: String, state: Arc<Mutex<VaultState>>) {
    let mut sink = vec![0u8; head.len() + 4];
    let _ = stream.read_exact(&mut sink).await;
    let (status, body) = {
        let mut s = state.lock().unwrap();
        s.hits += 1;
        s.auth.push(header(&head, "authorization").unwrap_or("").to_string());
        (s.status, s.body.clone())
    };
    let resp = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn start_mock(vault_body: String) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (htx, hrx) = mpsc::unbounded_channel();
    let (ktx, krx) = mpsc::unbounded_channel();
    let vault = Arc::new(Mutex::new(VaultState { status: 200, body: vault_body, hits: 0, auth: vec![] }));
    let keeper_status = Arc::new(Mutex::new(101u16));
    let (v, ks) = (vault.clone(), keeper_status.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let (htx, ktx, v, ks) = (htx.clone(), ktx.clone(), v.clone(), ks.clone());
            tokio::spawn(async move {
                let Some(head) = read_head(&mut stream).await else { return };
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                if path == "/api/vault" {
                    return serve_vault(stream, head, v).await;
                }
                let auth = header(&head, "authorization").map(str::to_string);
                let refuse = *ks.lock().unwrap();
                #[allow(clippy::result_large_err)] // the signature tungstenite asks for
                let cb = |_: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                    if path == "/api/keeper/ws" && refuse != 101 {
                        let mut e = ErrorResponse::new(None);
                        *e.status_mut() = StatusCode::from_u16(refuse).unwrap();
                        return Err(e);
                    }
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, cb).await else { return };
                match path.as_str() {
                    "/api/keeper/headless/ws" => {
                        let Some(Ok(Message::Text(t))) = ws.next().await else { return };
                        let _ = htx.send((serde_json::from_str(&t).unwrap(), ws));
                    }
                    "/api/keeper/ws" => {
                        let _ = ktx.send((auth, ws));
                    }
                    _ => {}
                }
            });
        }
    });
    Mock { port, headless: hrx, keeper: krx, vault, keeper_status }
}

// ───────────────────────────── fixtures ─────────────────────────────

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/rbkeeper-unlock-v1-vectors.json")).unwrap()
}

fn identity() -> Identity {
    let hex_seed = vectors()["identity"]["ed25519_seed_hex"].as_str().unwrap().to_string();
    let seed: [u8; 32] = hex::decode(hex_seed).unwrap().try_into().unwrap();
    Identity::from_seed(&seed)
}

fn blob() -> Vec<u8> {
    json!({"fields": {
        "bank|bank.example|#user": {"value": USER_VALUE, "auto": true},
        "bank|bank.example|#pass": {"value": PASS_VALUE, "auto": true},
        "bank|bank.example|#memo": {"value": MEMO_VALUE, "auto": false},
        "bank|bank.example|#otp": {"value": OTP_VALUE, "auto": true},
        "bank|bank.example|#gone": {"value": "x", "auto": true, "deleted": true},
    }, "cards": [{"number": "4111111111111111"}]})
    .to_string()
    .into_bytes()
}

fn vault_body(format: Format, password: &str, version: u64) -> String {
    let (ct, secret_id) = encrypt_for_tests(format, password, &[7u8; 16], &[9u8; 12], &blob());
    json!({"version": version, "secret_id": secret_id, "format": format.as_str(), "ciphertext": ct}).to_string()
}

fn payload(format: Format) -> Vec<u8> {
    json!({"v": 1, "device_token": TOKEN, "issued_at": 1_790_000_000,
           "vault": {"format": format.as_str(), "password": PASSWORD}})
    .to_string()
    .into_bytes()
}

fn config(port: u16) -> Config {
    let mut c = Config::new(Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap(), "testhost".into(), BOOT.into());
    c.deny_backoff = Duration::from_millis(300);
    c.rate_backoff = Duration::from_millis(300);
    c.resolved_retry = Duration::from_millis(20);
    c.retry_min = Duration::from_millis(20);
    c.retry_max = Duration::from_millis(200);
    c.skew_retry_min = Duration::from_millis(300);
    c.skew_retry_max = Duration::from_millis(600);
    c.unlock_wait = Duration::from_secs(5);
    c.vault_poll = Duration::from_secs(60);
    c.dead_after = Duration::from_secs(5);
    c.connect_timeout = Duration::from_secs(2);
    c
}

fn signed_fields(frame: &Value) -> RequestFields {
    let s = |k: &str| frame[k].as_str().unwrap().to_string();
    RequestFields { headless_id: s("headless_id"), boot_id: s("boot_id"), eph_pub: s("eph_pub"), ts: frame["ts"].as_i64().unwrap(), nonce: s("nonce") }
}

/// What the server checks on the first headless frame (§4).
fn assert_valid_request(frame: &Value, id: &Identity) {
    assert_eq!(frame["type"], "unlock_request");
    assert_eq!(frame["headless_id"], id.headless_id());
    assert_eq!(frame["boot_id"], BOOT);
    let keys: Vec<&String> = frame.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 7, "{:?}", keys);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    assert!((frame["ts"].as_i64().unwrap() - now).abs() <= 120);
    let sig: [u8; 64] = B64.decode(frame["sig"].as_str().unwrap()).unwrap().try_into().unwrap();
    let vk = VerifyingKey::from_bytes(&id.public_raw()).unwrap();
    vk.verify(&signed_fields(frame).signing_bytes().unwrap(), &Signature::from_bytes(&sig)).expect("signature verifies");
}

fn seal(eph_pub_b64: &str, info: &str, aad: &str, pt: &[u8]) -> (String, String) {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&B64.decode(eph_pub_b64).unwrap()).unwrap();
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk,
        info.as_bytes(),
        pt,
        aad.as_bytes(),
        &mut OsRng,
    )
    .unwrap();
    (B64.encode(enc.to_bytes()), B64.encode(ct))
}

async fn send(ws: &mut Sock, v: Value) {
    ws.send(Message::Text(v.to_string())).await.unwrap();
}

async fn close(ws: &mut Sock, code: u16, reason: &str) {
    let _ = ws.close(Some(CloseFrame { code: CloseCode::from(code), reason: reason.to_string().into() })).await;
}

async fn next_headless(m: &mut Mock) -> (Value, Sock) {
    timeout(WAIT, m.headless.recv()).await.expect("an unlock_request").unwrap()
}

async fn next_keeper(m: &mut Mock) -> (Option<String>, Sock) {
    timeout(WAIT, m.keeper.recv()).await.expect("a keeper connection").unwrap()
}

/// Approve the request on `ws` like a desktop Keeper would (§5 step 3).
async fn approve(ws: &mut Sock, frame: &Value, rid: &str, pt: &[u8]) {
    let info = hpke_info(frame["headless_id"].as_str().unwrap(), BOOT);
    let (enc, ct) = seal(frame["eph_pub"].as_str().unwrap(), &info, rid, pt);
    send(ws, json!({"type": "unlock_pending", "request_id": rid})).await;
    send(ws, json!({"type": "unlock_response", "request_id": rid, "enc": enc, "ciphertext": ct})).await;
}

async fn recv_json(ws: &mut Sock, within: Duration) -> Option<Value> {
    loop {
        match timeout(within, ws.next()).await {
            Err(_) => return None,
            Ok(Some(Ok(Message::Text(t)))) => return Some(serde_json::from_str(&t).unwrap()),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return None,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

/// Unlock through the mock and return the keeper socket after `device_info`.
async fn unlocked(m: &mut Mock, format: Format) -> (Value, Value, Option<String>, Sock) {
    let (first, mut hws) = next_headless(m).await;
    assert_valid_request(&first, &identity());
    approve(&mut hws, &first, "req-1", &payload(format)).await;
    let (auth, mut kws) = next_keeper(m).await;
    let info = recv_json(&mut kws, WAIT).await.expect("device_info");
    (first, info, auth, kws)
}

fn fill_request(rid: &str, fields: Value) -> Value {
    json!({"type": "fill_request", "request_id": rid, "session_id": "bank", "url": "https://www.bank.example/login",
           "message": "log in", "screenshot": "", "fields": fields})
}

fn spawn_daemon(port: u16) -> tokio::task::JoinHandle<Result<(), daemon::Fatal>> {
    spawn_daemon_with(config(port))
}

fn spawn_daemon_with(cfg: Config) -> tokio::task::JoinHandle<Result<(), daemon::Fatal>> {
    tokio::spawn(daemon::run(cfg, identity()))
}

// ───────────────────────────── tests ─────────────────────────────

#[tokio::test]
async fn unlocks_announces_headless_and_serves_only_all_auto_fills() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 4)).await;
    let d = spawn_daemon(m.port);
    let (_first, info, auth, mut ws) = unlocked(&mut m, Format::Sha256V2).await;

    assert_eq!(auth.as_deref(), Some(format!("Bearer {}", TOKEN).as_str()), "keeper socket uses the device token");
    assert_eq!(m.vault.lock().unwrap().auth, vec![format!("Bearer {}", TOKEN)], "one vault pull with the token");
    assert_eq!(info["type"], "device_info");
    assert_eq!(info["app"], "rb-keeperd");
    assert_eq!(info["device"]["platform"], "headless");
    assert_eq!(info["device"]["id"], identity().headless_id());
    assert_eq!(info["device"]["name"], "testhost");
    assert_eq!(info["vault"], json!({"schema": 1, "format": "aesgcm-sha256-v2", "has_key": true, "version": 4}));
    assert!(!info.to_string().contains("secret_id"), "device_info never carries secret_id");

    send(&mut ws, json!({"type": "ping"})).await;
    assert_eq!(recv_json(&mut ws, WAIT).await, Some(json!({"type": "pong"})));

    send(&mut ws, fill_request("f1", json!([{"selector": "#user", "field": "username", "label": "User"},
                                             {"selector": "#pass", "field": "password", "label": "Password"}]))).await;
    assert_eq!(
        recv_json(&mut ws, WAIT).await,
        Some(json!({"type": "fill_response", "request_id": "f1",
                    "values": [{"selector": "#user", "value": USER_VALUE}, {"selector": "#pass", "value": PASS_VALUE}]}))
    );

    // Silence for: a non-auto field, a one-time code (even stored auto), a missing or
    // deleted field, another session, and any secret_request.
    let mut other = fill_request("f6", json!([{"selector": "#user"}]));
    other["session_id"] = json!("mail");
    for (i, frame) in [
        fill_request("f2", json!([{"selector": "#user"}, {"selector": "#memo"}])),
        fill_request("f3", json!([{"selector": "#otp", "field": "code"}])),
        fill_request("f4", json!([{"selector": "#nope"}])),
        fill_request("f5", json!([{"selector": "#gone"}])),
        other,
        json!({"type": "secret_request", "request_id": "s1", "session_id": "bank", "secret": "card"}),
    ]
    .into_iter()
    .enumerate()
    {
        send(&mut ws, frame).await;
        assert_eq!(recv_json(&mut ws, QUIET).await, None, "case {} must get no answer", i);
    }
    // Still alive and serving after the silent ones.
    send(&mut ws, json!({"type": "ping"})).await;
    assert_eq!(recv_json(&mut ws, WAIT).await, Some(json!({"type": "pong"})));

    d.abort();
    let log = log_text();
    assert!(log.contains("comparison code"), "the comparison code is logged");
    assert!(log.contains("served 2 field(s)") && log.contains("left for a person"));
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn pbkdf2_vaults_unlock_too() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Pbkdf2V2, PASSWORD, 2)).await;
    let d = spawn_daemon(m.port);
    let (_first, info, _auth, mut ws) = unlocked(&mut m, Format::Pbkdf2V2).await;
    assert_eq!(info["vault"]["format"], "aesgcm-pbkdf2-v2");
    send(&mut ws, fill_request("p1", json!([{"selector": "#pass"}]))).await;
    let got = recv_json(&mut ws, WAIT).await.unwrap();
    assert_eq!(got["values"][0]["value"], PASS_VALUE);
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn timeout_and_cancel_retry_with_a_fresh_nonce_and_the_same_key() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (first, mut ws) = next_headless(&mut m).await;
    assert_valid_request(&first, &identity());
    send(&mut ws, json!({"type": "unlock_pending", "request_id": "r1"})).await;
    send(&mut ws, json!({"type": "unlock_resolved", "request_id": "r1", "status": "timeout"})).await;

    let (second, mut ws) = next_headless(&mut m).await;
    assert_valid_request(&second, &identity());
    assert_ne!(second["nonce"], first["nonce"], "fresh nonce");
    assert_eq!(second["eph_pub"], first["eph_pub"], "the unspent EK is reused");
    send(&mut ws, json!({"type": "unlock_pending", "request_id": "r2"})).await;
    send(&mut ws, json!({"type": "unlock_resolved", "request_id": "r2", "status": "cancelled"})).await;

    let (third, mut ws) = next_headless(&mut m).await;
    assert_ne!(third["nonce"], second["nonce"]);
    // An answer for some other request is not ours: the daemon drops the attempt.
    send(&mut ws, json!({"type": "unlock_pending", "request_id": "r3"})).await;
    send(&mut ws, json!({"type": "unlock_response", "request_id": "r-other", "denied": true})).await;
    let (fourth, mut ws) = next_headless(&mut m).await;
    assert_ne!(fourth["nonce"], third["nonce"]);
    approve(&mut ws, &fourth, "r4", &payload(Format::Sha256V2)).await;
    next_keeper(&mut m).await;
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn deny_backs_off_before_asking_again() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (_first, mut ws) = next_headless(&mut m).await;
    send(&mut ws, json!({"type": "unlock_pending", "request_id": "r1"})).await;
    let t0 = tokio::time::Instant::now();
    send(&mut ws, json!({"type": "unlock_response", "request_id": "r1", "denied": true})).await;
    let (_second, _ws) = next_headless(&mut m).await;
    assert!(t0.elapsed() >= Duration::from_millis(300), "waited deny_backoff, not {:?}", t0.elapsed());
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn close_1013_waits_the_rate_window() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (_first, mut ws) = next_headless(&mut m).await;
    let t0 = tokio::time::Instant::now();
    close(&mut ws, 1013, "rate limited").await;
    let (_second, _ws) = next_headless(&mut m).await;
    assert!(t0.elapsed() >= Duration::from_millis(300), "waited rate_backoff, not {:?}", t0.elapsed());
    d.abort();
}

#[tokio::test]
async fn close_1008_on_unlock_is_fatal() {
    capture_logs();
    // The server's identity refusal, its malformed-frame refusal, and a reason it may
    // add later all stop the daemon (main maps the Fatal to exit 78).
    for reason in ["unlock_request rejected", "malformed unlock_request", "something new"] {
        let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
        let d = spawn_daemon(m.port);
        let (_first, mut ws) = next_headless(&mut m).await;
        close(&mut ws, 1008, reason).await;
        let res = timeout(WAIT, d).await.expect("run returns").unwrap();
        let err = res.expect_err("1008 stops the daemon");
        assert!(err.0.contains("1008") && err.0.contains(reason), "{}", err.0);
        assert!(timeout(QUIET, m.headless.recv()).await.is_err(), "no further request after 1008 {}", reason);
    }
}

#[tokio::test]
async fn close_1008_stale_timestamp_backs_off_and_asks_again() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let mut cfg = config(m.port);
    // Over a second, so the retry's `ts` must differ if it is really re-stamped.
    cfg.skew_retry_min = Duration::from_millis(1100);
    cfg.skew_retry_max = Duration::from_millis(2200);
    let d = spawn_daemon_with(cfg);

    let (first, mut ws) = next_headless(&mut m).await;
    assert_valid_request(&first, &identity());
    let t0 = tokio::time::Instant::now();
    close(&mut ws, 1008, "stale timestamp").await;
    let (second, mut ws) = next_headless(&mut m).await;
    assert!(t0.elapsed() >= Duration::from_millis(1100), "waited skew_retry_min, not {:?}", t0.elapsed());
    assert!(!d.is_finished(), "a stale timestamp never stops the daemon");
    assert_valid_request(&second, &identity());
    assert_ne!(second["nonce"], first["nonce"], "fresh nonce");
    assert!(second["ts"].as_i64() > first["ts"].as_i64(), "fresh ts: {} then {}", first["ts"], second["ts"]);
    assert_eq!(second["eph_pub"], first["eph_pub"], "the unspent EK is reused");

    // Still off: the wait doubles.
    let t1 = tokio::time::Instant::now();
    close(&mut ws, 1008, "stale timestamp").await;
    let (third, mut ws) = next_headless(&mut m).await;
    assert!(t1.elapsed() >= Duration::from_millis(2200), "backoff doubled, not {:?}", t1.elapsed());
    assert_ne!(third["nonce"], second["nonce"]);
    assert_eq!(third["eph_pub"], first["eph_pub"]);

    // The clock is fixed: the mock accepts and a Keeper approves.
    approve(&mut ws, &third, "r3", &payload(Format::Sha256V2)).await;
    let (_auth, mut kws) = next_keeper(&mut m).await;
    assert_eq!(recv_json(&mut kws, WAIT).await.unwrap()["type"], "device_info");
    assert!(!d.is_finished());
    d.abort();
    assert!(log_text().contains("clock is off — check NTP"), "the WARN names the clock");
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn close_1008_replayed_nonce_asks_again_at_once() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let mut cfg = config(m.port);
    cfg.skew_retry_min = Duration::from_secs(30);
    cfg.retry_min = Duration::from_secs(30);
    let d = spawn_daemon_with(cfg);

    let (first, mut ws) = next_headless(&mut m).await;
    close(&mut ws, 1008, "replayed nonce").await;
    // Any backoff here would be 30 s; the retry comes well before that.
    let (second, mut ws) = timeout(Duration::from_secs(10), m.headless.recv()).await.expect("an immediate retry").unwrap();
    assert!(!d.is_finished(), "a replayed nonce never stops the daemon");
    assert_valid_request(&second, &identity());
    assert_ne!(second["nonce"], first["nonce"], "fresh nonce");
    assert!(second["ts"].as_i64() >= first["ts"].as_i64());
    assert_eq!(second["eph_pub"], first["eph_pub"], "the unspent EK is reused");
    approve(&mut ws, &second, "r2", &payload(Format::Sha256V2)).await;
    next_keeper(&mut m).await;
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn repeated_replayed_nonces_back_off() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let mut cfg = config(m.port);
    cfg.retry_min = Duration::from_millis(300);
    let d = spawn_daemon_with(cfg);
    let (_first, mut ws) = next_headless(&mut m).await;
    close(&mut ws, 1008, "replayed nonce").await;
    let (_second, mut ws) = next_headless(&mut m).await;
    let t0 = tokio::time::Instant::now();
    close(&mut ws, 1008, "replayed nonce").await;
    let (_third, _ws) = next_headless(&mut m).await;
    assert!(t0.elapsed() >= Duration::from_millis(300), "a second replay in a row waits retry_min, not {:?}", t0.elapsed());
    assert!(!d.is_finished());
    d.abort();
}

#[tokio::test]
async fn a_response_that_does_not_open_spends_the_key() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (first, mut ws) = next_headless(&mut m).await;
    // Sealed with the wrong info (another boot): open fails, and the EK is gone.
    let (enc, ct) = seal(first["eph_pub"].as_str().unwrap(), &hpke_info(&identity().headless_id(), "other-boot"), "r1", &payload(Format::Sha256V2));
    send(&mut ws, json!({"type": "unlock_pending", "request_id": "r1"})).await;
    send(&mut ws, json!({"type": "unlock_response", "request_id": "r1", "enc": enc, "ciphertext": ct})).await;
    let (second, _ws) = next_headless(&mut m).await;
    assert_ne!(second["eph_pub"], first["eph_pub"], "a spent EK is never reused");
    d.abort();
    assert_no_secret_logged(&[]);
}

async fn assert_relocks(m: &mut Mock, first: &Value) {
    let (again, mut ws) = next_headless(m).await;
    assert_valid_request(&again, &identity());
    assert_ne!(again["eph_pub"], first["eph_pub"], "re-unlock uses a new EK");
    // Unlock again and make sure the daemon is fully back.
    m.vault.lock().unwrap().status = 200;
    *m.keeper_status.lock().unwrap() = 101;
    approve(&mut ws, &again, "req-2", &payload(Format::Sha256V2)).await;
    let (_auth, mut kws) = next_keeper(m).await;
    assert_eq!(recv_json(&mut kws, WAIT).await.unwrap()["type"], "device_info");
}

#[tokio::test]
async fn a_vault_from_another_password_locks_and_asks_again() {
    capture_logs();
    // The server's vault was re-keyed (secret_id no longer matches our password).
    let mut m = start_mock(vault_body(Format::Sha256V2, "fixture-other-password-Qq5", 1)).await;
    let d = spawn_daemon(m.port);
    let (first, mut hws) = next_headless(&mut m).await;
    approve(&mut hws, &first, "req-1", &payload(Format::Sha256V2)).await;
    // Fix the vault only once the mismatched one was pulled, or a slow daemon reads the good one.
    timeout(WAIT, async {
        while m.vault.lock().unwrap().hits == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a vault pull");
    assert!(timeout(QUIET, m.keeper.recv()).await.is_err(), "no keeper socket with a mismatched key");
    m.vault.lock().unwrap().body = vault_body(Format::Sha256V2, PASSWORD, 2);
    assert_relocks(&mut m, &first).await;
    d.abort();
    assert!(log_text().contains("locked:"));
    assert_no_secret_logged(&["fixture-other-password-Qq5"]);
}

#[tokio::test]
async fn keeper_close_1008_locks_and_asks_again() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (first, _info, _auth, mut ws) = unlocked(&mut m, Format::Sha256V2).await;
    close(&mut ws, 1008, "revoked").await;
    assert_relocks(&mut m, &first).await;
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn a_refused_token_locks_and_asks_again() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (first, _info, _auth, mut ws) = unlocked(&mut m, Format::Sha256V2).await;
    // The token stops working: the vault answers 401 on the next pull.
    m.vault.lock().unwrap().status = 401;
    send(&mut ws, json!({"type": "vault_updated", "version": 9})).await;
    assert_relocks(&mut m, &first).await;
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn a_401_keeper_handshake_locks() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    *m.keeper_status.lock().unwrap() = 401;
    let d = spawn_daemon(m.port);
    let (first, mut hws) = next_headless(&mut m).await;
    approve(&mut hws, &first, "req-1", &payload(Format::Sha256V2)).await;
    assert_relocks(&mut m, &first).await;
    d.abort();
    assert_no_secret_logged(&[]);
}

#[tokio::test]
async fn transient_failures_do_not_lock() {
    capture_logs();
    let mut m = start_mock(vault_body(Format::Sha256V2, PASSWORD, 1)).await;
    let d = spawn_daemon(m.port);
    let (_first, _info, _auth, mut ws) = unlocked(&mut m, Format::Sha256V2).await;
    // A 500 on a pull keeps the held vault; a plain close reconnects with the same token.
    m.vault.lock().unwrap().status = 500;
    send(&mut ws, json!({"type": "vault_updated", "version": 2})).await;
    send(&mut ws, json!({"type": "ping"})).await;
    assert_eq!(recv_json(&mut ws, WAIT).await, Some(json!({"type": "pong"})));
    close(&mut ws, 1001, "going away").await;
    let (auth, mut ws) = next_keeper(&mut m).await;
    assert_eq!(auth.as_deref(), Some(format!("Bearer {}", TOKEN).as_str()));
    assert_eq!(recv_json(&mut ws, WAIT).await.unwrap()["vault"]["version"], 1, "still the held vault");
    // A vault_updated that is not newer does not pull.
    let hits = m.vault.lock().unwrap().hits;
    send(&mut ws, json!({"type": "vault_updated", "version": 1})).await;
    send(&mut ws, json!({"type": "ping"})).await;
    recv_json(&mut ws, WAIT).await;
    assert_eq!(m.vault.lock().unwrap().hits, hits);
    assert!(timeout(QUIET, m.headless.recv()).await.is_err(), "never went back to unlock");
    d.abort();
    assert_no_secret_logged(&[]);
}
