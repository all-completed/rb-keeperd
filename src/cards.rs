//! Saved payment cards from the vault, and the unattended card fill.
//!
//! A port of the desktop Keeper's `src/cards.js` (remote-browser-keeper):
//! `isCardOnlyRequest`, `autofillEnabled`, `findCardForDomain` (with `domainMatches`),
//! `cardValueForField` and `buildCardValues`, as `tryAutofillCard` in `main.js` chains
//! them. One deliberate difference: a `card-exp` whose month or year placeholder has
//! no digits on the card is unanswerable here, where the desktop would fill `00` or
//! an empty year (see `exp_from_template`).
//!
//! Card values are `SecretString`s: `Debug` prints `[REDACTED]`, drop zeroizes them.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

/// The billing address of a card (`card.billing`).
#[derive(Default)]
pub struct Billing {
    pub address_line1: SecretString,
    pub address_line2: SecretString,
    pub city: SecretString,
    pub zip: SecretString,
    pub state: SecretString,
    pub country: SecretString,
}

/// One live card. `id` and `domains` are labels, not card data, but `Debug` hides
/// them too: an id may be a person's name.
pub struct Card {
    pub id: String,
    pub holder: SecretString,
    pub number: SecretString,
    pub cvv: SecretString,
    pub exp_month: SecretString,
    pub exp_year: SecretString,
    pub billing: Billing,
    /// The hosts this card may be filled on silently (`*`, `*.example.com`, `example.com`).
    pub domains: Vec<String>,
}

impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Card").field("values", &"[REDACTED]").field("domains", &self.domains.len()).finish()
    }
}

/// `cardsMeta`: the auto-fill switch and the default card id.
pub struct CardsMeta {
    /// `autofill !== false`.
    pub autofill: bool,
    pub default: Option<String>,
}

impl Default for CardsMeta {
    fn default() -> Self {
        CardsMeta { autofill: true, default: None }
    }
}

impl fmt::Debug for CardsMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardsMeta").field("autofill", &self.autofill).field("default", &self.default.is_some()).finish()
    }
}

/// JS `String(v || "")` for a JSON scalar. Objects and arrays give "" rather than
/// `[object Object]`, so a malformed card is unanswerable instead of filled with junk.
fn js_or_empty(v: Option<Value>) -> Zeroizing<String> {
    Zeroizing::new(match v {
        Some(Value::String(s)) => s,
        Some(Value::Bool(true)) => "true".into(),
        Some(Value::Number(n)) => js_number(&n),
        _ => String::new(),
    })
}

/// JS `String(n)` for the numbers a card may carry (`12` → "12", `0` → "" via `||`).
fn js_number(n: &serde_json::Number) -> String {
    match n.as_f64() {
        Some(0.0) => String::new(),
        Some(f) if n.is_f64() => format!("{}", f),
        _ => n.to_string(),
    }
}

/// JS `String(v == null ? "" : v)`: like `js_or_empty`, but `0` stays "0".
fn js_nullish(v: Option<Value>) -> Zeroizing<String> {
    match v {
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => Zeroizing::new("0".into()),
        Some(Value::Bool(false)) => Zeroizing::new("false".into()),
        other => js_or_empty(other),
    }
}

fn secret(s: Zeroizing<String>) -> SecretString {
    let v = SecretString::from(String::clone(&s));
    crate::hardening::lock_in_ram(v.expose_secret().as_bytes());
    v
}

impl Card {
    /// A live card from its vault entry, or `None` for a tombstone (`deleted`) or a
    /// non-object. What is not taken out is scrubbed by the caller.
    fn from_entry(id: String, e: &mut Value) -> Option<Card> {
        let Value::Object(m) = e else { return None };
        if m.get("deleted").map(crate::vault::truthy).unwrap_or(false) {
            return None;
        }
        let holder = secret(js_or_empty(m.remove("holder")));
        let number = secret(js_or_empty(m.remove("number")));
        let cvv = secret(js_or_empty(m.remove("cvv")));
        let exp_month = secret(js_nullish(m.remove("exp_month")));
        let exp_year = secret(js_nullish(m.remove("exp_year")));
        let billing = match m.get_mut("billing") {
            Some(Value::Object(b)) => Billing {
                address_line1: secret(js_or_empty(b.remove("address_line1"))),
                address_line2: secret(js_or_empty(b.remove("address_line2"))),
                city: secret(js_or_empty(b.remove("city"))),
                zip: secret(js_or_empty(b.remove("zip"))),
                state: secret(js_or_empty(b.remove("state"))),
                country: secret(js_or_empty(b.remove("country"))),
            },
            _ => Billing::default(),
        };
        let domains = match m.remove("domains") {
            Some(Value::Array(a)) => a.into_iter().map(|d| String::clone(&js_or_empty(Some(d)))).collect(),
            _ => Vec::new(),
        };
        Some(Card { id, holder, number, cvv, exp_month, exp_year, billing, domains })
    }
}

/// The `cards` map with its keys in the order JS `Object.keys` gives them: array
/// indices ("0", "1", …) ascending first, then the rest in insertion order.
#[derive(Default)]
struct OrderedCards(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for OrderedCards {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OrderedCards;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a cards map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<OrderedCards, A::Error> {
                let mut out: Vec<(String, Value)> = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    // JSON.parse keeps the last value of a repeated key, at its first position.
                    match out.iter_mut().find(|(id, _)| *id == k) {
                        Some(slot) => crate::vault::scrub(&mut std::mem::replace(&mut slot.1, v)),
                        None => out.push((k, v)),
                    }
                }
                out.sort_by_key(|(k, _)| array_index(k).map_or((1, 0), |i| (0, i)));
                Ok(OrderedCards(out))
            }
            // Anything but an object holds no usable card (desktop: `cards || {}`).
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<OrderedCards, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(OrderedCards::default())
            }
            fn visit_unit<E: de::Error>(self) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<OrderedCards, E> {
                Ok(OrderedCards::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// A canonical array index (`0`, `7`, `42`, not `07` or `4294967295`), as JS orders keys.
fn array_index(k: &str) -> Option<u32> {
    if k.is_empty() || (k.len() > 1 && k.starts_with('0')) || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    k.parse::<u32>().ok().filter(|&i| i != u32::MAX)
}

#[derive(Default, Deserialize)]
struct CardsPart {
    #[serde(default)]
    cards: OrderedCards,
    #[serde(default, rename = "cardsMeta")]
    meta: Option<Value>,
}

/// Live cards (in desktop order) and `cardsMeta` from the decrypted blob text. A
/// `cards` or `cardsMeta` of the wrong shape yields no cards, never an error: the
/// parser's error could quote a value.
pub fn from_blob(blob: &str) -> (Vec<Card>, CardsMeta) {
    let CardsPart { cards, mut meta } = serde_json::from_str(blob).unwrap_or_default();
    let mut out = Vec::new();
    for (id, mut e) in cards.0 {
        if let Some(c) = Card::from_entry(id, &mut e) {
            out.push(c);
        }
        crate::vault::scrub(&mut e);
    }
    let mut cm = CardsMeta::default();
    if let Some(Value::Object(m)) = meta.as_mut() {
        cm.autofill = m.get("autofill") != Some(&Value::Bool(false));
        cm.default = Some(String::clone(&js_or_empty(m.remove("default")))).filter(|s| !s.is_empty());
    }
    if let Some(m) = meta.as_mut() {
        crate::vault::scrub(m);
    }
    (out, cm)
}

/// `isCardOnlyRequest`: a non-empty list whose every `field` kind, lowercased (not
/// trimmed), starts with `card-`.
pub fn is_card_only_request(fields: &[Value]) -> bool {
    !fields.is_empty()
        && fields.iter().all(|f| f.get("field").and_then(Value::as_str).map(|k| k.to_lowercase().starts_with("card-")).unwrap_or(false))
}

/// `domainMatches`: `*` is every site; `*.a.com`, `www.a.com` and `a.com` all mean
/// `a.com` and its subdomains.
pub fn domain_matches(approved: &str, host: &str) -> bool {
    if approved == "*" {
        return true;
    }
    let a = approved.to_lowercase();
    let a = a.strip_prefix("*.").unwrap_or(&a);
    let a = a.strip_prefix("www.").unwrap_or(a);
    !a.is_empty() && !host.is_empty() && (host == a || host.ends_with(&format!(".{}", a)))
}

/// `findCardForDomain`: the default card first (when it is live), then the others in
/// order; the first one approved for `host`.
pub fn card_for_host<'a>(cards: &'a [Card], meta: &CardsMeta, host: &str) -> Option<&'a Card> {
    if host.is_empty() {
        return None;
    }
    let def = meta.default.as_deref().and_then(|d| cards.iter().find(|c| c.id == d));
    def.into_iter()
        .chain(cards.iter().filter(|c| Some(c.id.as_str()) != def.map(|d| d.id.as_str())))
        .find(|c| c.domains.iter().any(|d| domain_matches(d, host)))
}

fn digits(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.chars().filter(char::is_ascii_digit).collect())
}

/// `String.replace(/C{min,max}/g, rep)`.
fn replace_runs(s: &str, ch: char, min: usize, max: usize, rep: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut run = 0usize;
    let flush = |out: &mut String, run: &mut usize| {
        while *run >= min {
            out.push_str(rep);
            *run -= (*run).min(max);
        }
        out.extend(std::iter::repeat_n(ch, *run));
        *run = 0;
    };
    for c in s.chars() {
        if c == ch {
            run += 1;
        } else {
            flush(&mut out, &mut run);
            out.push(c);
        }
    }
    flush(&mut out, &mut run);
    out
}

/// `expFromTemplate(card, cardExpTemplate(format))`. The template is `format` when it
/// has an M or Y (either case), else `MM/YY`; only uppercase runs are replaced, as on
/// the desktop. Stricter than the desktop: when a month or year placeholder would be
/// replaced but the card has no digits for it, the result is "" (unanswerable), not
/// `00` or a missing year.
fn exp_from_template(card: &Card, format: Option<&str>) -> Zeroizing<String> {
    let template = match format {
        Some(f) if f.chars().any(|c| matches!(c, 'M' | 'Y' | 'm' | 'y')) => f,
        _ => "MM/YY",
    };
    let m = digits(card.exp_month.expose_secret());
    let yraw = digits(card.exp_year.expose_secret());
    if (template.contains('M') && m.is_empty()) || (template.contains('Y') && yraw.is_empty()) {
        return Zeroizing::new(String::new());
    }
    let padded = Zeroizing::new(format!("{:0>2}", m.as_str()));
    let mm = &padded[padded.len() - 2..];
    let yyyy = Zeroizing::new(match yraw.len() {
        n if n >= 4 => yraw[n - 4..].to_string(),
        2 => format!("20{}", yraw.as_str()),
        _ => yraw.to_string(),
    });
    let yy = &yyyy[yyyy.len().saturating_sub(2)..];
    let t = replace_runs(template, 'Y', 3, 4, &yyyy);
    let t = replace_runs(&t, 'Y', 1, 2, yy);
    replace_runs(&t, 'M', 1, 2, mm)
}

/// `billingValue`: every non-empty part joined by ", " when `format` is blank, else
/// the listed `ADDRESS_LINE1,ADDRESS_LINE2,CITY,ZIP,STATE,COUNTRY` tokens in order.
fn billing_value(b: &Billing, format: Option<&str>) -> Zeroizing<String> {
    let part = |token: &str| -> Option<&SecretString> {
        Some(match token {
            "ADDRESS_LINE1" => &b.address_line1,
            "ADDRESS_LINE2" => &b.address_line2,
            "CITY" => &b.city,
            "ZIP" => &b.zip,
            "STATE" => &b.state,
            "COUNTRY" => &b.country,
            _ => return None,
        })
    };
    let parts: Vec<&SecretString> = match format.filter(|f| !f.trim().is_empty()) {
        None => vec![&b.address_line1, &b.address_line2, &b.city, &b.zip, &b.state, &b.country],
        Some(f) => f.split(',').filter_map(|t| part(&t.trim().to_uppercase())).collect(),
    };
    let kept: Vec<&str> = parts.iter().map(|s| s.expose_secret()).filter(|s| !s.is_empty()).collect();
    Zeroizing::new(kept.join(", "))
}

/// `cardValueForField`: the value for one card-* kind, or `None` when the kind is not
/// a card field this Keeper knows.
pub fn card_value_for_field(kind: &str, format: Option<&str>, card: &Card) -> Option<SecretString> {
    let v = match kind.to_lowercase().as_str() {
        "card-holder-name" => Zeroizing::new(card.holder.expose_secret().to_string()),
        "card-number" => digits(card.number.expose_secret()),
        "card-cvv" => Zeroizing::new(card.cvv.expose_secret().to_string()),
        "card-exp" => exp_from_template(card, format),
        "card-billing-address" => billing_value(&card.billing, format),
        _ => return None,
    };
    Some(secret(v))
}

/// `buildCardValues`: one `(selector, value)` per field, or `None` when the card
/// cannot satisfy every field. Only the billing address may be empty; an empty
/// number, holder, expiry or CVV — nobody is here to type it — means no answer.
pub fn build_card_values<'f>(fields: &'f [Value], card: &Card) -> Option<Vec<(&'f str, SecretString)>> {
    let mut out = Vec::with_capacity(fields.len());
    for f in fields {
        let kind = f.get("field").and_then(Value::as_str).unwrap_or("").to_lowercase();
        let selector = f.get("selector").and_then(Value::as_str)?;
        let value = card_value_for_field(&kind, f.get("format").and_then(Value::as_str), card)?;
        if kind != "card-billing-address" && value.expose_secret().is_empty() {
            return None;
        }
        out.push((selector, value));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MARK: &str = "fixture-card-mark";

    // Raw text, not `json!`: serde_json's map sorts keys, and the order is under test.
    fn blob() -> String {
        r#"{"fields": {}, "cards": {
            "work": {"holder": "WORK HOLDER fixture-card-mark", "number": "4000 0000 0000 0002", "cvv": "fixture-card-mark-cvv",
                     "exp_month": 3, "exp_year": "28", "domains": ["shop.example"], "updated_at": "x"},
            "home": {"holder": "HOME HOLDER", "number": "4111-1111-1111-1111", "cvv": "123", "exp_month": "11", "exp_year": 2031,
                     "billing": {"address_line1": "1 fixture-card-mark St", "city": "Town", "zip": "12345", "country": "US"},
                     "domains": ["*.shop.example", "other.example"]},
            "gone": {"deleted": true, "updated_at": "y", "number": "4999999999999999", "domains": ["*"]},
            "bare": "fixture-card-mark-bare",
            "7": {"number": "4222222222222", "cvv": "1", "exp_month": "1", "exp_year": "2030", "domains": ["seven.example"]}
        }, "cardsMeta": {"autofill": true, "default": "home", "updated_at": "z"}}"#
            .to_string()
    }

    fn field(kind: &str, format: Option<&str>) -> Value {
        let mut f = json!({"selector": format!("#{}", kind), "field": kind});
        if let Some(fmt) = format {
            f["format"] = json!(fmt);
        }
        f
    }

    fn value(kind: &str, format: Option<&str>, card: &Card) -> Option<String> {
        card_value_for_field(kind, format, card).map(|s| s.expose_secret().to_string())
    }

    #[test]
    fn live_cards_keep_js_key_order_and_meta() {
        let (cards, meta) = from_blob(&blob());
        let ids: Vec<&str> = cards.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["7", "work", "home"], "array-index keys first; tombstones and non-objects dropped");
        assert!(meta.autofill);
        assert_eq!(meta.default.as_deref(), Some("home"));
        assert_eq!(cards[1].exp_month.expose_secret(), "3");
        assert_eq!(cards[2].exp_year.expose_secret(), "2031");
        assert_eq!(cards[2].billing.zip.expose_secret(), "12345");
        assert_eq!(cards[2].domains, vec!["*.shop.example", "other.example"]);
    }

    #[test]
    fn malformed_cards_and_meta_are_empty_not_errors() {
        for b in [r#"{"cards":[{"number":"4111"}]}"#, r#"{"cards":null}"#, r#"{"cards":"x"}"#, r#"{}"#, "[]", r#"{"cards":{"a":1}}"#] {
            let (cards, meta) = from_blob(b);
            assert!(cards.is_empty(), "{}", b);
            assert!(meta.autofill && meta.default.is_none(), "{}", b);
        }
        for (m, on) in [(json!({"autofill": false}), false), (json!({"autofill": null}), true), (json!({"autofill": 0}), true), (json!("x"), true)] {
            let (_, meta) = from_blob(&json!({"cards": {}, "cardsMeta": m}).to_string());
            assert_eq!(meta.autofill, on, "only a literal false turns auto-fill off: {}", m);
        }
    }

    #[test]
    fn domains_match_like_the_desktop() {
        assert!(domain_matches("*", "anything.example"));
        assert!(domain_matches("shop.example", "shop.example"));
        assert!(domain_matches("shop.example", "pay.shop.example"));
        assert!(domain_matches("*.shop.example", "shop.example"));
        assert!(domain_matches("WWW.Shop.Example", "shop.example"));
        assert!(!domain_matches("shop.example", "evilshop.example"));
        assert!(!domain_matches("pay.shop.example", "shop.example"));
        assert!(!domain_matches("", "shop.example"));
        assert!(!domain_matches("shop.example", ""));
    }

    #[test]
    fn the_default_card_is_preferred_then_the_others_in_order() {
        let (cards, meta) = from_blob(&blob());
        assert_eq!(card_for_host(&cards, &meta, "shop.example").unwrap().id, "home", "default first");
        assert_eq!(card_for_host(&cards, &meta, "seven.example").unwrap().id, "7");
        assert!(card_for_host(&cards, &meta, "elsewhere.example").is_none(), "the tombstone's * never applies");
        assert!(card_for_host(&cards, &meta, "").is_none());
        let other = CardsMeta { autofill: true, default: Some("nope".into()) };
        assert_eq!(card_for_host(&cards, &other, "shop.example").unwrap().id, "work", "unknown default: plain order");
        let none = CardsMeta::default();
        assert_eq!(card_for_host(&cards, &none, "shop.example").unwrap().id, "work");
    }

    #[test]
    fn values_map_like_the_desktop() {
        let (cards, _) = from_blob(&blob());
        let (work, home) = (&cards[1], &cards[2]);
        assert_eq!(value("card-number", None, home).unwrap(), "4111111111111111");
        assert_eq!(value("CARD-Holder-Name", None, home).unwrap(), "HOME HOLDER");
        assert_eq!(value("card-cvv", None, home).unwrap(), "123");
        assert_eq!(value("card-exp", None, home).unwrap(), "11/31");
        assert_eq!(value("card-exp", Some("exp date"), home).unwrap(), "11/31", "no M/Y: MM/YY");
        assert_eq!(value("card-exp", Some("MM/YYYY"), home).unwrap(), "11/2031");
        assert_eq!(value("card-exp", Some("YYYY-MM"), home).unwrap(), "2031-11");
        assert_eq!(value("card-exp", Some("MMYY"), home).unwrap(), "1131");
        assert_eq!(value("card-exp", Some("M / YYY"), home).unwrap(), "11 / 2031");
        assert_eq!(value("card-exp", Some("YYYYYY"), home).unwrap(), "203131", "Y{{3,4}} then Y{{1,2}}");
        assert_eq!(value("card-exp", Some("mm/yy"), home).unwrap(), "mm/yy", "desktop replaces uppercase runs only");
        assert_eq!(value("card-exp", Some("MM/YYYY"), work).unwrap(), "03/2028", "month padded, 2-digit year → 20xx");
        assert_eq!(value("card-billing-address", None, home).unwrap(), "1 fixture-card-mark St, Town, 12345, US");
        assert_eq!(value("card-billing-address", Some(" zip , Country,bogus"), home).unwrap(), "12345, US");
        assert_eq!(value("card-billing-address", Some("STATE"), home).unwrap(), "");
        assert_eq!(value("card-billing-address", None, work).unwrap(), "", "no billing at all");
        assert!(value("card-type", None, home).is_none(), "unknown card kind");
    }

    #[test]
    fn a_missing_expiry_part_is_unanswerable_not_00() {
        let (cards, _) = from_blob(r#"{"cards":{"a":{"number":"4111","exp_year":"2030"},"b":{"number":"4111","exp_month":"5"}}}"#);
        assert_eq!(value("card-exp", None, &cards[0]).unwrap(), "");
        assert_eq!(value("card-exp", Some("YYYY"), &cards[0]).unwrap(), "2030", "the month is not asked for");
        assert_eq!(value("card-exp", Some("MM/YY"), &cards[1]).unwrap(), "");
        assert_eq!(value("card-exp", Some("MM"), &cards[1]).unwrap(), "05");
    }

    #[test]
    fn card_only_and_build_values() {
        assert!(is_card_only_request(&[field("card-number", None), field("CARD-cvv", None)]));
        assert!(!is_card_only_request(&[]));
        assert!(!is_card_only_request(&[field("card-number", None), field("username", None)]));
        assert!(!is_card_only_request(&[json!({"selector": "#x"})]));
        assert!(!is_card_only_request(&[field(" card-number", None)]), "kinds are not trimmed (desktop)");

        let (cards, _) = from_blob(&blob());
        let home = &cards[2];
        let fields = [field("card-number", None), field("card-exp", Some("MM/YY")), field("card-billing-address", Some("STATE"))];
        let got = build_card_values(&fields, home).expect("billing may be empty");
        let got: Vec<(&str, &str)> = got.iter().map(|(s, v)| (*s, v.expose_secret())).collect();
        assert_eq!(got, vec![("#card-number", "4111111111111111"), ("#card-exp", "11/31"), ("#card-billing-address", "")]);

        let (nocvv, _) = from_blob(r#"{"cards":{"a":{"holder":"H","number":"4111","exp_month":"1","exp_year":"30"}}}"#);
        assert!(build_card_values(&[field("card-number", None), field("card-cvv", None)], &nocvv[0]).is_none(), "no CVV: never an empty fill");
        assert!(build_card_values(&[field("card-number", None)], &nocvv[0]).is_some());
        assert!(build_card_values(&[field("card-type", None)], home).is_none());
        assert!(build_card_values(&[json!({"field": "card-number"})], home).is_none(), "no selector");
    }

    #[test]
    fn debug_shows_no_card_values() {
        let (cards, meta) = from_blob(&blob());
        let dbg = format!("{:?} {:?} {:?}", cards, meta, cards.iter().map(|c| card_value_for_field("card-cvv", None, c)).collect::<Vec<_>>());
        for needle in [MARK, "4111", "4000", "HOLDER", "home", "work", "shop.example", "12345"] {
            assert!(!dbg.contains(needle), "{:?} in {}", needle, dbg);
        }
    }
}
