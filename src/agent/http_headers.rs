//! Structured HTTP header validation shared by policy (pre-execution)
//! and the HTTP provider (defense in depth). Headers are a map of names
//! to values — never a delimiter-separated string anywhere past the
//! legacy migration adapter.
//!
//! Nothing here knows about any application: names follow RFC 7230
//! tokens, values must be single-line, counts and lengths are bounded.

use std::collections::BTreeMap;

/// Upper bound on header count per request (abuse/size guard).
pub const MAX_HEADERS: usize = 32;
/// Upper bound on a single header value (tokens are ~1KB; headroom kept).
pub const MAX_HEADER_VALUE_LEN: usize = 8192;

/// RFC 7230 token: `!#$%&'*+-.^_`|~`, digits, letters.
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
        })
}

/// A header value must be a single line: no CR, LF, or NUL (those are
/// request-smuggling / client-rejection hazards), within the length cap.
pub fn validate_header_value(value: &str) -> Result<(), String> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err("header value must be a single line (no CR/LF)".to_string());
    }
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err(format!(
            "header value exceeds {MAX_HEADER_VALUE_LEN} bytes (got {})",
            value.len()
        ));
    }
    Ok(())
}

/// Validate a full header map. Returns the pairs in sorted (canonical)
/// order for deterministic fingerprints and request building.
pub fn validate_header_map(map: &BTreeMap<String, String>) -> Result<Vec<(String, String)>, String> {
    if map.len() > MAX_HEADERS {
        return Err(format!(
            "too many headers (got {}, max {MAX_HEADERS})",
            map.len()
        ));
    }
    let mut out = Vec::with_capacity(map.len());
    let mut seen: Vec<String> = Vec::new();
    for (name, value) in map {
        if !is_valid_header_name(name) {
            return Err(format!(
                "invalid header name `{name}`: use an RFC 7230 token (letters, digits, `-`) without spaces or colons"
            ));
        }
        let lowered = name.to_ascii_lowercase();
        if seen.contains(&lowered) {
            return Err(format!("duplicate header `{name}` (header names are case-insensitive)"));
        }
        seen.push(lowered);
        validate_header_value(value).map_err(|e| format!("header `{name}`: {e}"))?;
        out.push((name.clone(), value.clone()));
    }
    Ok(out)
}

/// Legacy migration adapter: the old `;`-separated string form. Accepts
/// ONLY strict `Name: value` pairs split on `;`. Newline- or comma-joined
/// blobs are AMBIGUOUS (commas and line breaks are legal inside values)
/// and are rejected with an error that names the object format — never
/// silently merged into one header.
pub fn parse_legacy_headers(raw: &str) -> Result<Vec<(String, String)>, String> {
    if raw.contains('\n') || raw.contains('\r') {
        return Err(
            "headers joined with newlines are ambiguous: pass an object instead, e.g. {\"Authorization\": \"Bearer <token>\", \"Content-Type\": \"application/json\"}".to_string(),
        );
    }
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for piece in raw.split(';') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let Some((name, value)) = piece.split_once(':') else {
            return Err(format!(
                "header piece `{piece}` has no `Name: value` shape — pass an object instead, e.g. {{\"Authorization\": \"Bearer <token>\"}}"
            ));
        };
        let name = name.trim();
        let value = value.trim();
        if !is_valid_header_name(name) {
            return Err(format!(
                "invalid header name `{name}`: use an RFC 7230 token without spaces or colons"
            ));
        }
        // A comma inside a legacy piece means two headers were glued
        // together (commas never separate headers in this contract):
        // reject rather than guess the split.
        if value.contains(',') && looks_like_glued_headers(value) {
            return Err(
                "headers appear comma-joined (e.g. \"Authorization: Bearer x, Content-Type: ...\") — that merges into ONE malformed header. Pass an object instead, e.g. {\"Authorization\": \"Bearer <token>\", \"Content-Type\": \"application/json\"}".to_string(),
            );
        }
        let lowered = name.to_ascii_lowercase();
        if seen.contains(&lowered) {
            return Err(format!("duplicate header `{name}` (header names are case-insensitive)"));
        }
        seen.push(lowered);
        validate_header_value(value).map_err(|e| format!("header `{name}`: {e}"))?;
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}

/// Heuristic for the observed failure mode: `Bearer <token>, Word:` —
/// a second `Name:` pattern after a comma means glued headers, not a
/// legitimate comma-containing value.
fn looks_like_glued_headers(value: &str) -> bool {
    let Some((_, after)) = value.split_once(',') else {
        return false;
    };
    let after = after.trim();
    // `Token [...]` followed by `Word:` — colon-terminated word ahead.
    if let Some((word, _)) = after.split_once(':') {
        let word = word.trim();
        return !word.is_empty()
            && word.len() <= 64
            && word.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    }
    false
}

/// Header names only, for traces/evidence/logs. Values never leave the
/// request builder.
pub fn header_names(pairs: &[(String, String)]) -> Vec<String> {
    pairs.iter().map(|(n, _)| n.clone()).collect()
}

/// Does the header set include Content-Type (case-insensitive)?
pub fn has_content_type(pairs: &[(String, String)]) -> bool {
    pairs
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-type"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn valid_names_pass() {
        for good in ["Authorization", "Content-Type", "X-Custom-1", "Accept", "a"] {
            assert!(is_valid_header_name(good), "{good}");
        }
    }

    #[test]
    fn invalid_names_fail() {
        for bad in ["", "Bad Name", "No:Colon", "semi;colon", "ünïcodé", "a b"] {
            assert!(!is_valid_header_name(bad), "{bad}");
        }
    }

    #[test]
    fn values_must_be_single_line() {
        assert!(validate_header_value("Bearer abc").is_ok());
        assert!(validate_header_value("a\nb").is_err());
        assert!(validate_header_value("a\rb").is_err());
        assert!(validate_header_value(&"x".repeat(9000)).is_err());
    }

    #[test]
    fn map_validates_pairs_and_sorts() {
        let pairs = validate_header_map(&map(&[
            ("X-B", "1"),
            ("Authorization", "Bearer x"),
        ]))
        .unwrap();
        assert_eq!(pairs[0].0, "Authorization");
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn map_rejects_bad_name_and_multiline_value() {
        assert!(validate_header_map(&map(&[("Bad Name", "v")])).is_err());
        assert!(validate_header_map(&map(&[("X-A", "a\nb")])).is_err());
    }

    #[test]
    fn map_rejects_case_insensitive_duplicates() {
        assert!(validate_header_map(&map(&[
            ("Content-Type", "a"),
            ("content-type", "b")
        ]))
        .is_err());
    }

    #[test]
    fn legacy_strict_form_parses() {
        let pairs = parse_legacy_headers("Authorization: Bearer x; Content-Type: application/json")
            .unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("Authorization".to_string(), "Bearer x".to_string()));
    }

    #[test]
    fn legacy_newline_form_rejected() {
        let err = parse_legacy_headers("Authorization: Bearer x\nContent-Type: y").unwrap_err();
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn legacy_comma_glued_rejected() {
        let err = parse_legacy_headers(
            "Authorization: Bearer x, Content-Type: application/json",
        )
        .unwrap_err();
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn legacy_missing_colon_rejected() {
        assert!(parse_legacy_headers("garbage").is_err());
    }
}
