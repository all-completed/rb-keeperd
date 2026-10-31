//! Which `fill_request`s the daemon answers (rbkeeper-unlock-v1 §9).
//!
//! The rule is the desktop Keeper's silent-fill decision, unchanged
//! (`onetimecode.js autofillValues` + `fieldstore.js keyOf/getSaved` +
//! `cards.js hostFromUrl`): answer only when EVERY requested field has a live vault
//! entry marked auto and none is a one-time code. Anything else gets no answer at
//! all, so the request stays open for a person on a desktop Keeper. The daemon has
//! no prompt and never cancels or denies.

use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use crate::vault::Vault;

/// `new URL(url).hostname.toLowerCase().replace(/^www\./, "")`, or "" when the URL
/// does not parse.
pub fn host_from_url(raw: &str) -> String {
    let Ok(u) = url::Url::parse(raw) else { return String::new() };
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    match host.strip_prefix("www.") {
        Some(rest) => rest.to_string(),
        None => host,
    }
}

/// `session|host|selector`, with session and selector trimmed (`keyOf`).
pub fn key_of(session: &str, host: &str, selector: &str) -> String {
    format!("{}|{}|{}", session.trim(), host, selector.trim())
}

/// `isOneTimeCode`: the REQUEST's field kind, trimmed and lowercased, is "code".
pub fn is_one_time_code(field: &Value) -> bool {
    field.get("field").and_then(Value::as_str).map(|k| k.trim().eq_ignore_ascii_case("code")).unwrap_or(false)
}

/// One `{selector, value}` of a `fill_response`. `Debug` hides the value.
pub struct Fill {
    pub selector: Value,
    pub value: SecretString,
}

impl std::fmt::Debug for Fill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fill").field("selector", &self.selector).field("value", &"[REDACTED]").finish()
    }
}

/// The silent-fill decision for one `fill_request` frame: the values to send, or
/// `None` to stay silent.
pub fn decide_fill(vault: &Vault, req: &Value) -> Option<Vec<Fill>> {
    let fields = req.get("fields")?.as_array()?;
    if fields.is_empty() {
        return None;
    }
    let session = req.get("session_id").and_then(Value::as_str).unwrap_or("");
    let host = host_from_url(req.get("url").and_then(Value::as_str).unwrap_or(""));
    let mut out = Vec::with_capacity(fields.len());
    for f in fields {
        if !f.is_object() || is_one_time_code(f) {
            return None;
        }
        // The server always sends string selectors; anything else is not ours to guess.
        let selector = f.get("selector").and_then(Value::as_str)?;
        let entry = vault.fields.get(&key_of(session, &host, selector))?;
        if !entry.auto {
            return None;
        }
        out.push(Fill { selector: Value::String(selector.to_string()), value: entry.value.clone() });
    }
    Some(out)
}

/// The `fill_response` frame text. The caller zeroizes it after sending.
pub fn fill_response(request_id: &str, fills: &[Fill]) -> zeroize::Zeroizing<String> {
    let values: Vec<Value> = fills
        .iter()
        .map(|f| serde_json::json!({"selector": f.selector, "value": f.value.expose_secret()}))
        .collect();
    let frame = serde_json::json!({"type": "fill_response", "request_id": request_id, "values": values});
    zeroize::Zeroizing::new(frame.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Entry, Format};
    use serde_json::json;

    fn vault() -> Vault {
        let mut v = Vault { version: 3, format: Some(Format::Sha256V2), ..Default::default() };
        let mut put = |k: &str, val: &str, auto: bool| {
            v.fields.insert(k.into(), Entry { value: SecretString::from(val.to_string()), auto });
        };
        put("bank|bank.example|#user", "fixture-user", true);
        put("bank|bank.example|#pass", "fixture-pass", true);
        put("bank|bank.example|#memo", "fixture-memo", false);
        put("bank|bank.example|#otp", "fixture-old-code", true);
        v
    }

    fn req(url: &str, session: &str, fields: Value) -> Value {
        json!({"type": "fill_request", "request_id": "r1", "session_id": session, "url": url,
               "message": "log in", "screenshot": "", "fields": fields})
    }

    fn values(fills: &[Fill]) -> Vec<(String, String)> {
        fills.iter().map(|f| (f.selector.as_str().unwrap().into(), f.value.expose_secret().into())).collect()
    }

    #[test]
    fn all_auto_fields_are_answered() {
        let r = req("https://bank.example/login", "bank",
            json!([{"selector": "#user", "label": "User", "field": "username"},
                   {"selector": "#pass", "label": "Password", "field": "password"}]));
        let fills = decide_fill(&vault(), &r).expect("all auto");
        assert_eq!(values(&fills), vec![("#user".into(), "fixture-user".into()), ("#pass".into(), "fixture-pass".into())]);
        let frame: Value = serde_json::from_str(&fill_response("r1", &fills)).unwrap();
        assert_eq!(frame, json!({"type": "fill_response", "request_id": "r1",
            "values": [{"selector": "#user", "value": "fixture-user"}, {"selector": "#pass", "value": "fixture-pass"}]}));
    }

    #[test]
    fn one_non_auto_or_missing_field_silences_the_whole_request() {
        let v = vault();
        let mixed = req("https://bank.example/", "bank", json!([{"selector": "#user"}, {"selector": "#memo"}]));
        assert!(decide_fill(&v, &mixed).is_none(), "non-auto");
        let missing = req("https://bank.example/", "bank", json!([{"selector": "#user"}, {"selector": "#nope"}]));
        assert!(decide_fill(&v, &missing).is_none(), "missing");
        let other_session = req("https://bank.example/", "mail", json!([{"selector": "#user"}]));
        assert!(decide_fill(&v, &other_session).is_none(), "session is part of the key");
        let other_host = req("https://evil.example/", "bank", json!([{"selector": "#user"}]));
        assert!(decide_fill(&v, &other_host).is_none(), "host is part of the key");
        let sub = req("https://login.bank.example/", "bank", json!([{"selector": "#user"}]));
        assert!(decide_fill(&v, &sub).is_none(), "subdomains do not match");
    }

    #[test]
    fn a_one_time_code_is_never_served_even_if_stored_auto() {
        let v = vault();
        for kind in ["code", " Code ", "CODE"] {
            let r = req("https://bank.example/", "bank", json!([{"selector": "#otp", "field": kind}]));
            assert!(decide_fill(&v, &r).is_none(), "{:?}", kind);
            let r = req("https://bank.example/", "bank", json!([{"selector": "#user"}, {"selector": "#otp", "field": kind}]));
            assert!(decide_fill(&v, &r).is_none(), "{:?} with others", kind);
        }
        // The stored entry is only reachable when the request does not call it a code.
        let r = req("https://bank.example/", "bank", json!([{"selector": "#otp", "field": "text"}]));
        assert!(decide_fill(&v, &r).is_some());
    }

    #[test]
    fn hosts_and_keys_normalise_like_the_desktop() {
        assert_eq!(host_from_url("https://WWW.Bank.Example:8443/a?b#c"), "bank.example");
        assert_eq!(host_from_url("https://www.www.bank.example/"), "www.bank.example", "one www. only");
        assert_eq!(host_from_url("https://user:pw@bank.example/"), "bank.example");
        assert_eq!(host_from_url("not a url"), "");
        assert_eq!(host_from_url(""), "");
        assert_eq!(key_of("  bank ", "bank.example", " #user\t"), "bank|bank.example|#user");

        let v = vault();
        let r = req("https://www.BANK.example/login", " bank ", json!([{"selector": "  #user "}]));
        let fills = decide_fill(&v, &r).expect("normalised match");
        assert_eq!(fills[0].selector, json!("  #user "), "the response echoes the request's selector");
    }

    #[test]
    fn malformed_requests_are_silent() {
        let v = vault();
        for fields in [json!([]), json!(null), json!("x"), json!([null]), json!([{"label": "no selector"}]), json!([{"selector": 7}])] {
            assert!(decide_fill(&v, &req("https://bank.example/", "bank", fields.clone())).is_none(), "{}", fields);
        }
        assert!(decide_fill(&v, &json!({"type": "fill_request"})).is_none());
        assert!(decide_fill(&Vault::default(), &req("https://bank.example/", "bank", json!([{"selector": "#user"}]))).is_none());
    }

    #[test]
    fn fill_debug_redacts() {
        let fills = decide_fill(&vault(), &req("https://bank.example/", "bank", json!([{"selector": "#pass"}]))).unwrap();
        assert!(!format!("{:?}", fills).contains("fixture-pass"));
    }
}
