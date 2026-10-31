//! The `rbkeeperd run` state machine (rbkeeper-unlock-v1 §5–§9).
//!
//! ```text
//!   locked ──unlock_request──▶ waiting ──approved──▶ unlocked (keeper WS, fills)
//!     ▲                          │ timeout/cancel: same EK, fresh nonce+ts
//!     │                          │ denied: ~60 min, 1013: the hour, 1008: stop
//!     └── wipe token+password ◀──┴── keeper close 1008 / 401 / vault key mismatch
//! ```
//!
//! Secrets held while unlocked: the device token and the vault password (in the
//! `UnlockPayload`, `SecretString`s) and the decrypted vault (`Vault`, also
//! `SecretString`s). Locking drops them, which zeroizes them; so does a SIGTERM,
//! because `main` drops the whole `run` future before exiting.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use secrecy::ExposeSecret;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, timeout_at, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::serve;
use crate::unlock::{self, Answer, EphemeralKey, RequestFields, UnlockPayload};
use crate::vault::{self, Vault, VaultError};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub const HEADLESS_WS_PATH: &str = "api/keeper/headless/ws";
pub const KEEPER_WS_PATH: &str = "api/keeper/ws";

/// Close codes the server uses on the headless socket (§6).
const CLOSE_POLICY: u16 = 1008;
const CLOSE_TRY_AGAIN_LATER: u16 = 1013;

/// Everything the daemon needs besides its identity. All waits are fields so the
/// integration tests can shrink them; `Config::new` has the production values.
#[derive(Debug, Clone)]
pub struct Config {
    /// Server base URL, normalised to end with `/`.
    pub server: Url,
    pub hostname: String,
    pub boot_id: String,
    pub version: String,
    /// After a person denies the unlock (§8: about 60 min).
    pub deny_backoff: Duration,
    /// After close 1013 (more than 10 requests in the hour, §6).
    pub rate_backoff: Duration,
    /// Pause before re-requesting after `unlock_resolved` timeout/cancelled.
    pub resolved_retry: Duration,
    /// Exponential backoff for transport failures.
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// How long one unlock request may stay open. The server resolves it as
    /// `timeout` after 300 s (§6); waiting less would cancel it early, so this is
    /// never below 300 s in production.
    pub unlock_wait: Duration,
    /// Periodic vault pull while unlocked (§8: every 10 min).
    pub vault_poll: Duration,
    /// The server pings every 25 s; this much silence means the socket is dead.
    pub dead_after: Duration,
    pub connect_timeout: Duration,
}

/// The server allows 300 s for a person to answer; the daemon must not give up first.
pub const SERVER_UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);

impl Config {
    pub fn new(server: Url, hostname: String, boot_id: String) -> Self {
        Config {
            server: normalise_base(server),
            hostname,
            boot_id,
            version: env!("CARGO_PKG_VERSION").to_string(),
            deny_backoff: Duration::from_secs(60 * 60),
            rate_backoff: Duration::from_secs(60 * 60),
            resolved_retry: Duration::from_secs(2),
            retry_min: Duration::from_secs(5),
            retry_max: Duration::from_secs(300),
            unlock_wait: SERVER_UNLOCK_TIMEOUT + Duration::from_secs(60),
            vault_poll: Duration::from_secs(10 * 60),
            dead_after: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(20),
        }
    }

    pub fn ws_url(&self, path: &str) -> Url {
        let mut u = self.server.join(path).expect("relative path joins");
        let scheme = if u.scheme() == "https" { "wss" } else { "ws" };
        u.set_scheme(scheme).expect("ws scheme");
        u
    }
}

fn normalise_base(mut u: Url) -> Url {
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    u.set_query(None);
    u.set_fragment(None);
    u
}

/// Only https, except plain http to a loopback host (the tests' mock server).
pub fn check_server_url(u: &Url) -> Result<(), String> {
    match u.scheme() {
        "https" => Ok(()),
        "http" if matches!(u.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]")) => Ok(()),
        s => Err(format!("server URL must be https:// (got {}://)", s)),
    }
}

/// The run cannot continue: the server refused this identity (headless close 1008:
/// not enrolled, revoked, bad signature, clock skew). Restarting will not help, so
/// `main` exits 78 and the unit's `RestartPreventExitStatus=78` keeps it down.
#[derive(Debug)]
pub struct Fatal(pub String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A server-supplied close reason, made safe to log.
fn reason_text(frame: &Option<CloseFrame<'_>>) -> String {
    frame
        .as_ref()
        .map(|f| f.reason.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(120).collect())
        .unwrap_or_default()
}

fn close_code(frame: &Option<CloseFrame<'_>>) -> Option<u16> {
    frame.as_ref().map(|f| u16::from(f.code))
}

struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    fn new(min: Duration, max: Duration) -> Self {
        Backoff { min, max, next: min }
    }
    fn next(&mut self) -> Duration {
        let d = self.next;
        self.next = (self.next * 2).min(self.max);
        d
    }
    fn reset(&mut self) {
        self.next = self.min;
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// tungstenite::Error is large; it is the crate's own type and lives briefly.
#[allow(clippy::result_large_err)]
async fn connect(cfg: &Config, req: tungstenite::handshake::client::Request) -> Result<Ws, tungstenite::Error> {
    match timeout(cfg.connect_timeout, tokio_tungstenite::connect_async(req)).await {
        Ok(r) => r.map(|(ws, _resp)| ws),
        Err(_) => Err(tungstenite::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))),
    }
}

/// A transport error, described without anything the peer sent in a body.
fn describe(e: &tungstenite::Error) -> String {
    match e {
        tungstenite::Error::Http(resp) => format!("HTTP {}", resp.status().as_u16()),
        tungstenite::Error::Io(e) => format!("io: {}", e.kind()),
        other => other.to_string().chars().take(160).collect(),
    }
}

// ───────────────────────────── unlock (§5, §8) ─────────────────────────────

enum Attempt {
    Unlocked(UnlockPayload),
    Denied,
    Resolved(String),
    RateLimited(String),
    Rejected(String),
    Failed(String),
}

fn new_ephemeral(cfg: &Config, identity: &Identity) -> EphemeralKey {
    let ek = EphemeralKey::generate();
    info!(
        "unlock: {} on boot {} — comparison code {} (check it on the Keeper before approving)",
        identity.headless_id(),
        cfg.boot_id,
        unlock::comparison_code(&ek.public_raw(), &cfg.boot_id)
    );
    ek
}

/// Ask a person on a desktop Keeper to unlock this boot, until one approves.
/// Errors only on a 1008 refusal.
pub async fn unlock(cfg: &Config, identity: &Identity) -> Result<UnlockPayload, Fatal> {
    let mut ek = new_ephemeral(cfg, identity);
    let mut backoff = Backoff::new(cfg.retry_min, cfg.retry_max);
    loop {
        if ek.is_spent() {
            ek = new_ephemeral(cfg, identity);
        }
        match unlock_attempt(cfg, identity, &mut ek).await {
            Attempt::Unlocked(payload) => {
                ek.wipe();
                return Ok(payload);
            }
            Attempt::Denied => {
                backoff.reset();
                warn!("unlock: denied on the Keeper; asking again in {}s", cfg.deny_backoff.as_secs());
                sleep(cfg.deny_backoff).await;
            }
            Attempt::Resolved(status) => {
                backoff.reset();
                info!("unlock: request ended ({}); asking again with a fresh nonce", status);
                sleep(cfg.resolved_retry).await;
            }
            Attempt::RateLimited(reason) => {
                warn!("unlock: rate limited (1013 {}); waiting {}s", reason, cfg.rate_backoff.as_secs());
                sleep(cfg.rate_backoff).await;
            }
            Attempt::Rejected(reason) => {
                ek.wipe();
                return Err(Fatal(format!(
                    "server refused this identity (1008 {}); is it enrolled on a Keeper and the clock in sync?",
                    reason
                )));
            }
            Attempt::Failed(why) => {
                let d = backoff.next();
                warn!("unlock: {}; retrying in {}s", why, d.as_secs());
                sleep(d).await;
            }
        }
    }
}

async fn unlock_attempt(cfg: &Config, identity: &Identity, ek: &mut EphemeralKey) -> Attempt {
    let req = match cfg.ws_url(HEADLESS_WS_PATH).as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => return Attempt::Failed(describe(&e)),
    };
    let mut ws = match connect(cfg, req).await {
        Ok(ws) => ws,
        Err(e) => return Attempt::Failed(format!("connect: {}", describe(&e))),
    };
    let fields = RequestFields {
        headless_id: identity.headless_id(),
        boot_id: cfg.boot_id.clone(),
        eph_pub: ek.public_b64(),
        ts: now_secs(),
        nonce: unlock::fresh_nonce(),
    };
    let frame = match fields.signed_frame(identity) {
        Ok(f) => f,
        // boot_id comes from the kernel; a non-ASCII one cannot be signed (§2).
        Err(e) => return Attempt::Rejected(e.to_string()),
    };
    if let Err(e) = ws.send(Message::Text(frame)).await {
        return Attempt::Failed(format!("send: {}", describe(&e)));
    }
    let result = await_answer(cfg, identity, ek, &mut ws).await;
    // A disconnect is how the daemon cancels; after an answer the server closes anyway.
    let _ = ws.close(None).await;
    result
}

async fn await_answer(cfg: &Config, identity: &Identity, ek: &mut EphemeralKey, ws: &mut Ws) -> Attempt {
    let deadline = Instant::now() + cfg.unlock_wait;
    let mut pending: Option<String> = None;
    loop {
        let msg = match timeout_at(deadline, ws.next()).await {
            Err(_) => return Attempt::Failed(format!("no answer in {}s", cfg.unlock_wait.as_secs())),
            Ok(None) => return Attempt::Failed("socket ended without an answer".into()),
            Ok(Some(Err(e))) => return Attempt::Failed(describe(&e)),
            Ok(Some(Ok(m))) => m,
        };
        match msg {
            Message::Text(text) => {
                let Some(rid) = pending.as_deref() else {
                    match unlock::parse_pending(&text) {
                        Some(rid) => {
                            info!("unlock: request {} is waiting for a Keeper", rid);
                            pending = Some(rid);
                        }
                        None => debug!("unlock: ignoring a frame before unlock_pending"),
                    }
                    continue;
                };
                match unlock::parse_answer(&text, rid) {
                    Ok(None) => continue,
                    Ok(Some(Answer::Denied)) => return Attempt::Denied,
                    Ok(Some(Answer::Resolved(status))) => return Attempt::Resolved(status),
                    Ok(Some(Answer::Approved { enc, ciphertext })) => {
                        let info = unlock::hpke_info(&identity.headless_id(), &cfg.boot_id);
                        // `open` consumes the private key whatever the outcome (§8: zeroize EK).
                        let pt = match ek.open(info.as_bytes(), rid.as_bytes(), &enc, &ciphertext) {
                            Ok(pt) => pt,
                            Err(e) => return Attempt::Failed(format!("approved response does not open: {}", e)),
                        };
                        return match UnlockPayload::parse(&pt) {
                            Ok(p) => {
                                info!("unlock: approved (vault format {})", p.vault_format.as_str());
                                Attempt::Unlocked(p)
                            }
                            Err(e) => Attempt::Failed(e.to_string()),
                        };
                    }
                    Err(e) => return Attempt::Failed(e.to_string()),
                }
            }
            Message::Close(frame) => {
                let reason = reason_text(&frame);
                return match close_code(&frame) {
                    Some(CLOSE_POLICY) => Attempt::Rejected(reason),
                    Some(CLOSE_TRY_AGAIN_LATER) => Attempt::RateLimited(reason),
                    code => Attempt::Failed(format!("closed {:?} {} without an answer", code, reason)),
                };
            }
            Message::Binary(_) => return Attempt::Failed("unexpected binary frame".into()),
            _ => continue,
        }
    }
}

// ─────────────────────────── unlocked: keeper WS (§7, §9) ───────────────────────────

/// Why the daemon dropped its keys and went back to `unlock`.
#[derive(Debug)]
pub struct Locked(pub String);

enum SessionEnd {
    Lock(String),
    Retry(String),
}

async fn pull(client: &reqwest::Client, cfg: &Config, p: &UnlockPayload) -> Result<Vault, VaultError> {
    vault::pull(client, &cfg.server, &p.device_token, p.vault_format, &p.vault_password).await
}

/// Serve fills with this unlock until something says the keys are no longer good.
pub async fn keeper(cfg: &Config, identity: &Identity, client: &reqwest::Client, payload: &UnlockPayload) -> Locked {
    let mut backoff = Backoff::new(cfg.retry_min, cfg.retry_max);
    let mut held: Option<Vault> = None;
    loop {
        let vault = match held.take() {
            Some(v) => v,
            None => match pull(client, cfg, payload).await {
                Ok(v) => {
                    info!("vault: version {} with {} fields", v.version, v.len());
                    v
                }
                Err(e) if e.locks() => return Locked(e.to_string()),
                Err(e) => {
                    let d = backoff.next();
                    warn!("vault: {}; retrying in {}s", e, d.as_secs());
                    sleep(d).await;
                    continue;
                }
            },
        };
        let mut vault = vault;
        let (connected, end) = session(cfg, identity, client, payload, &mut vault).await;
        held = Some(vault);
        match end {
            SessionEnd::Lock(why) => return Locked(why),
            SessionEnd::Retry(why) => {
                if connected {
                    backoff.reset();
                }
                let d = backoff.next();
                warn!("keeper: {}; reconnecting in {}s", why, d.as_secs());
                sleep(d).await;
            }
        }
    }
}

fn device_info(cfg: &Config, identity: &Identity, payload: &UnlockPayload, vault: &Vault) -> String {
    json!({
        "type": "device_info",
        "app": "rb-keeperd",
        "version": cfg.version,
        "device": {
            "id": identity.headless_id(),
            "name": cfg.hostname,
            "platform": "headless",
            "app_version": cfg.version,
        },
        "vault": {
            "schema": 1,
            "format": vault.format.unwrap_or(payload.vault_format).as_str(),
            "has_key": true,
            "version": vault.version,
        },
    })
    .to_string()
}

/// Replace the held vault after a pull; `Some` when the result means lock.
fn apply_pull(vault: &mut Vault, pulled: Result<Vault, VaultError>) -> Option<String> {
    match pulled {
        Ok(v) => {
            if v.version != vault.version {
                info!("vault: now version {} with {} fields", v.version, v.len());
            }
            *vault = v;
            None
        }
        Err(e) if e.locks() => Some(e.to_string()),
        Err(e) => {
            warn!("vault: {}; keeping version {}", e, vault.version);
            None
        }
    }
}

async fn session(
    cfg: &Config,
    identity: &Identity,
    client: &reqwest::Client,
    payload: &UnlockPayload,
    vault: &mut Vault,
) -> (bool, SessionEnd) {
    let mut req = match cfg.ws_url(KEEPER_WS_PATH).as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => return (false, SessionEnd::Retry(describe(&e))),
    };
    let bearer = Zeroizing::new(format!("Bearer {}", payload.device_token.expose_secret()));
    let Ok(mut auth) = HeaderValue::from_str(&bearer) else {
        return (false, SessionEnd::Lock("device token is not a valid header value".into()));
    };
    drop(bearer);
    auth.set_sensitive(true);
    req.headers_mut().insert(AUTHORIZATION, auth);
    let mut ws = match connect(cfg, req).await {
        Ok(ws) => ws,
        Err(tungstenite::Error::Http(resp)) if resp.status().as_u16() == 401 => {
            return (false, SessionEnd::Lock("keeper socket refused the device token (401)".into()))
        }
        Err(e) => return (false, SessionEnd::Retry(format!("connect: {}", describe(&e)))),
    };
    info!("keeper: connected as {} ({})", identity.headless_id(), cfg.hostname);
    if let Err(e) = ws.send(Message::Text(device_info(cfg, identity, payload, vault))).await {
        return (true, SessionEnd::Retry(format!("send: {}", describe(&e))));
    }
    let end = serve_loop(cfg, client, payload, vault, &mut ws).await;
    let _ = ws.close(None).await;
    (true, end)
}

async fn send_text(ws: &mut Ws, text: String) -> Result<(), SessionEnd> {
    ws.send(Message::Text(text)).await.map_err(|e| SessionEnd::Retry(format!("send: {}", describe(&e))))
}

async fn serve_loop(
    cfg: &Config,
    client: &reqwest::Client,
    payload: &UnlockPayload,
    vault: &mut Vault,
    ws: &mut Ws,
) -> SessionEnd {
    let mut poll = tokio::time::interval_at(Instant::now() + cfg.vault_poll, cfg.vault_poll);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let msg = tokio::select! {
            m = timeout(cfg.dead_after, ws.next()) => m,
            _ = poll.tick() => {
                if let Some(why) = apply_pull(vault, pull(client, cfg, payload).await) {
                    return SessionEnd::Lock(why);
                }
                continue;
            }
        };
        let msg = match msg {
            Err(_) => return SessionEnd::Retry(format!("no frame in {}s", cfg.dead_after.as_secs())),
            Ok(None) => return SessionEnd::Retry("socket ended".into()),
            Ok(Some(Err(e))) => return SessionEnd::Retry(describe(&e)),
            Ok(Some(Ok(m))) => m,
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(frame) => {
                let reason = reason_text(&frame);
                return match close_code(&frame) {
                    // §7: unenrolled / revoked device token.
                    Some(CLOSE_POLICY) => SessionEnd::Lock(format!("keeper socket closed 1008 {}", reason)),
                    code => SessionEnd::Retry(format!("closed {:?} {}", code, reason)),
                };
            }
            _ => continue,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            debug!("keeper: ignoring a non-JSON frame");
            continue;
        };
        match frame.get("type").and_then(Value::as_str).unwrap_or("") {
            "ping" => {
                if let Err(end) = send_text(ws, json!({"type": "pong"}).to_string()).await {
                    return end;
                }
            }
            "fill_request" => {
                let rid = frame.get("request_id").and_then(Value::as_str).unwrap_or("");
                let session = frame.get("session_id").and_then(Value::as_str).unwrap_or("");
                let host = serve::host_from_url(frame.get("url").and_then(Value::as_str).unwrap_or(""));
                match serve::decide_fill(vault, &frame) {
                    Some(fills) if !rid.is_empty() => {
                        let mut out = serve::fill_response(rid, &fills);
                        info!("fill: {} for session {:?} on {} — served {} field(s)", rid, session, host, fills.len());
                        drop(fills);
                        // The String moves into tungstenite's frame buffer; that copy is not
                        // ours to zeroize (README "Limits"), ours is emptied here.
                        if let Err(end) = send_text(ws, std::mem::take(&mut *out)).await {
                            return end;
                        }
                    }
                    _ => info!("fill: {} for session {:?} on {} — left for a person", rid, session, host),
                }
            }
            "vault_updated" => {
                let newer = frame.get("version").and_then(Value::as_u64).map(|v| v > vault.version).unwrap_or(true);
                if newer {
                    if let Some(why) = apply_pull(vault, pull(client, cfg, payload).await) {
                        return SessionEnd::Lock(why);
                    }
                }
            }
            // secret_request is never answered by a headless Keeper (§9); request_resolved
            // and anything new are ignored.
            other => debug!("keeper: ignoring {:?}", other),
        }
    }
}

/// Unlock, serve, and on any lock condition wipe and unlock again with a new EK.
/// Returns only on a fatal refusal; SIGTERM is handled by dropping this future.
pub async fn run(cfg: Config, identity: Identity) -> Result<(), Fatal> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(cfg.connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Fatal(format!("HTTP client: {}", e)))?;
    info!("rb-keeperd {} for {} at {}", cfg.version, identity.headless_id(), cfg.server);
    loop {
        let payload = unlock(&cfg, &identity).await?;
        let Locked(why) = keeper(&cfg, &identity, &client, &payload).await;
        drop(payload);
        error!("locked: {}; keys wiped, asking for a new unlock", why);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_normalise_and_map_to_ws() {
        let cfg = Config::new(Url::parse("https://rb.example/base?x=1").unwrap(), "h".into(), "b".into());
        assert_eq!(cfg.server.as_str(), "https://rb.example/base/");
        assert_eq!(cfg.ws_url(HEADLESS_WS_PATH).as_str(), "wss://rb.example/base/api/keeper/headless/ws");
        assert_eq!(cfg.ws_url(KEEPER_WS_PATH).as_str(), "wss://rb.example/base/api/keeper/ws");
        let local = Config::new(Url::parse("http://127.0.0.1:9").unwrap(), "h".into(), "b".into());
        assert_eq!(local.ws_url(KEEPER_WS_PATH).as_str(), "ws://127.0.0.1:9/api/keeper/ws");
    }

    #[test]
    fn only_https_or_loopback_http() {
        assert!(check_server_url(&Url::parse("https://rb.example/").unwrap()).is_ok());
        assert!(check_server_url(&Url::parse("http://127.0.0.1:8080/").unwrap()).is_ok());
        assert!(check_server_url(&Url::parse("http://rb.example/").unwrap()).is_err());
        assert!(check_server_url(&Url::parse("ws://rb.example/").unwrap()).is_err());
    }

    #[test]
    fn production_unlock_wait_outlasts_the_server_timeout() {
        let cfg = Config::new(Url::parse("https://rb.example/").unwrap(), "h".into(), "b".into());
        assert!(cfg.unlock_wait > SERVER_UNLOCK_TIMEOUT, "§6: the server resolves at 300 s; never cut it short");
        assert_eq!(cfg.deny_backoff, Duration::from_secs(3600));
        assert_eq!(cfg.vault_poll, Duration::from_secs(600));
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(30));
        let seq: Vec<u64> = (0..5).map(|_| b.next().as_secs()).collect();
        assert_eq!(seq, vec![5, 10, 20, 30, 30]);
        b.reset();
        assert_eq!(b.next().as_secs(), 5);
    }
}
