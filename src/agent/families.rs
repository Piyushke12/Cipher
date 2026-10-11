//! Vulnerability family registry: investigation domains, not rigid modes.
//!
//! Generic security objectives — no application-specific paths,
//! credentials, fingerprints, or attack sequences.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityQuestion {
    pub question: String,
    pub resolving_capabilities: Vec<String>,
    pub priority: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityFamily {
    pub id: String,
    pub name: String,
    pub objective: String,
    pub questions: Vec<SecurityQuestion>,
    pub relevant_capabilities: Vec<String>,
    pub priority: u8,
}

fn q(question: &str, caps: &[&str], priority: u8) -> SecurityQuestion {
    SecurityQuestion {
        question: question.to_string(),
        resolving_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        priority,
    }
}

fn fam(
    id: &str,
    name: &str,
    objective: &str,
    questions: Vec<SecurityQuestion>,
    relevant_capabilities: &[&str],
    priority: u8,
) -> VulnerabilityFamily {
    VulnerabilityFamily {
        id: id.to_string(),
        name: name.to_string(),
        objective: objective.to_string(),
        questions,
        relevant_capabilities: relevant_capabilities.iter().map(|s| s.to_string()).collect(),
        priority,
    }
}

/// Generic keyword-based family inference for model-reported findings.
/// No application-specific fingerprints: matches broad weakness classes
/// only, defaults to `miscellaneous`.
pub fn infer_family(title: &str, detail: &str) -> &'static str {
    let t = format!("{title} {detail}").to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| t.contains(w));
    if has(&["sqli", "sql injection", "injection", "ssti", "command injection", "ldap", "xpath"]) {
        "injection"
    } else if has(&["xss", "cross-site scripting", "script injection"]) {
        "xss"
    } else if has(&["bola", "idor", "broken access", "unauthorized access", "privilege", "forbidden", "403", "401"]) {
        "broken_access_control"
    } else if has(&["auth bypass", "authentication", "session", "login bypass", "jwt"]) {
        "broken_authentication"
    } else if has(&["secret", "credential", "api key", "token exposed", "sensitive data", "pii"]) {
        "sensitive_data_exposure"
    } else if has(&["tls", "ssl", "certificate", "crypto", "cipher", "signature"]) {
        "cryptographic_issues"
    } else if has(&["xxe", "external entity"]) {
        "xxe"
    } else if has(&["redirect", "open redirect"]) {
        "unvalidated_redirects"
    } else if has(&["deserial"]) {
        "insecure_deserialization"
    } else if has(&["rate limit", "brute force", "captcha", "lockout"]) {
        "broken_anti_automation"
    } else if has(&["misconfig", "debug", "directory listing", "default page", "verbose error", "header"]) {
        "security_misconfiguration"
    } else if has(&["outdated", "vulnerable component", "cve-", "dependency"]) {
        "vulnerable_components"
    } else {
        "miscellaneous"
    }
}

/// Full generic taxonomy. Each family lists representative questions and
/// the capabilities (from the existing CapabilityRegistry) that can help.
/// `focus = <id>` boosts priority; it never filters other families.
pub fn builtin_families() -> Vec<VulnerabilityFamily> {
    vec![
        fam("injection", "Injection", "Determine whether untrusted input reaches interpreters and can be validated safely.",
            vec![
                q("Which inputs reach interpreters?", &["http.parameter_discovery", "api.schema_discovery"], 80),
                q("Which parameters affect backend behavior?", &["web.injection_testing", "http.request"], 85),
                q("Is there evidence of syntax/semantic injection?", &["web.injection_testing", "http.request"], 90),
                q("Can a suspected injection be validated safely?", &["web.injection_testing", "http.request"], 90),
            ], &["http.parameter_discovery", "api.schema_discovery", "web.injection_testing", "http.request"], 90),
        fam("broken_access_control", "Broken Access Control", "Verify authorization boundaries across identities and roles.",
            vec![
                q("Are sensitive resources accessible without authentication?", &["http.request", "api.auth_testing"], 90),
                q("Can one identity access another identity's resources?", &["api.bola_testing", "http.request"], 90),
                q("Can a low-privileged identity reach privileged functionality?", &["api.auth_testing", "http.request"], 85),
                q("Are object identifiers properly authorized?", &["api.bola_testing"], 85),
                q("Are administrative endpoints protected?", &["http.request", "api.auth_testing"], 80),
            ], &["http.request", "api.auth_testing", "api.bola_testing"], 90),
        fam("broken_authentication", "Broken Authentication", "Assess identity verification and session management.",
            vec![
                q("Are weak or default credentials accepted?", &["http.request", "api.auth_testing"], 85),
                q("Are session tokens guessable, reusable, or unexpired?", &["http.request"], 75),
                q("Is authentication bypass possible?", &["api.auth_testing", "http.request"], 90),
            ], &["http.request", "api.auth_testing"], 85),
        fam("xss", "Cross-Site Scripting", "Determine whether user-controlled input is rendered without safe encoding.",
            vec![
                q("Are reflected inputs rendered without encoding?", &["http.request", "web.dynamic_testing"], 70),
                q("Is stored user content rendered unsafely?", &["web.dynamic_testing", "browser.dom.inspect"], 70),
                q("Can script execution be demonstrated safely?", &["browser.dom.inspect", "http.request"], 75),
            ], &["http.request", "web.dynamic_testing", "browser.dom.inspect"], 70),
        fam("sensitive_data_exposure", "Sensitive Data Exposure", "Identify sensitive data reachable beyond its trust boundary.",
            vec![
                q("Is sensitive data transmitted or stored without protection?", &["http.request", "source.secret_detection"], 80),
                q("Are secrets exposed client-side or in artifacts?", &["source.secret_detection", "browser.network.observe"], 80),
            ], &["http.request", "source.secret_detection", "browser.network.observe"], 80),
        fam("security_misconfiguration", "Security Misconfiguration", "Detect unsafe defaults, verbose errors, and exposed interfaces.",
            vec![
                q("Are verbose errors or debug interfaces exposed?", &["http.probe", "http.request"], 65),
                q("Are insecure HTTP methods or headers accepted?", &["http.request"], 60),
            ], &["http.probe", "http.request"], 65),
        fam("cryptographic_issues", "Cryptographic Issues", "Verify tokens, signatures, and algorithms are sound.",
            vec![
                q("Are sensitive values merely encoded rather than protected?", &["http.request"], 70),
                q("Are tokens signed and signatures verified?", &["http.request", "api.auth_testing"], 75),
                q("Are weak algorithms in use?", &["external.tls_discovery", "http.request"], 65),
            ], &["http.request", "api.auth_testing", "external.tls_discovery"], 70),
        fam("improper_input_validation", "Improper Input Validation", "Check trust in client-supplied values and types.",
            vec![q("Are type/range/length constraints enforced server-side?", &["http.request", "web.fuzzing"], 60)],
            &["http.request", "web.fuzzing"], 60),
        fam("unvalidated_redirects", "Unvalidated Redirects", "Check whether redirects/forwards can be controlled.",
            vec![q("Can redirect destinations be controlled cross-origin?", &["http.request"], 55)],
            &["http.request"], 55),
        fam("vulnerable_components", "Vulnerable Components", "Inventory dependencies and match known-vulnerable versions.",
            vec![
                q("Which third-party components/versions are deployed?", &["dependency.scan", "sbom.generate"], 70),
                q("Arefix-available vulnerable versions present?", &["dependency.scan", "vulnerability.lookup"], 70),
            ], &["dependency.scan", "sbom.generate", "vulnerability.lookup"], 70),
        fam("security_through_obscurity", "Security Through Obscurity", "Verify hidden endpoints are still authorized.",
            vec![q("Are undisclosed endpoints reachable and authorized?", &["http.endpoint_discovery", "http.request"], 55)],
            &["http.endpoint_discovery", "http.request"], 55),
        fam("insecure_deserialization", "Insecure Deserialization", "Assess handling of serialized objects.",
            vec![q("Do serialized inputs influence privileged behavior?", &["http.request", "web.injection_testing"], 60)],
            &["http.request", "web.injection_testing"], 60),
        fam("broken_anti_automation", "Broken Anti-Automation", "Test rate limits, lockouts, and abuse controls.",
            vec![
                q("Are rate limits enforced on sensitive operations?", &["api.rate_limit_testing", "http.request"], 60),
                q("Are account-enumeration or brute-force guards present?", &["api.rate_limit_testing"], 60),
            ], &["api.rate_limit_testing", "http.request"], 60),
        fam("observability_failures", "Observability Failures", "Check logging/monitoring of security-relevant events.",
            vec![q("Are authentication/authorization failures logged?", &["http.request", "configuration.audit"], 45)],
            &["http.request", "configuration.audit"], 45),
        fam("xxe", "XML External Entities", "Determine whether XML input resolves external entities.",
            vec![q("Does XML input resolve external entities?", &["http.request", "web.injection_testing"], 55)],
            &["http.request", "web.injection_testing"], 55),
        fam("miscellaneous", "Miscellaneous", "Catch-all for findings outside the above domains.",
            vec![q("Is there residual unexplained attack surface?", &["http.probe", "http.crawl"], 40)],
            &["http.probe", "http.crawl", "http.request"], 40),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn full_taxonomy_loads_with_questions_and_caps() {
        let fams = builtin_families();
        assert!(fams.len() >= 16);
        let ids: HashSet<_> = fams.iter().map(|f| f.id.as_str()).collect();
        for expected in ["injection", "broken_access_control", "broken_authentication", "xss",
            "sensitive_data_exposure", "security_misconfiguration", "cryptographic_issues",
            "improper_input_validation", "unvalidated_redirects", "vulnerable_components",
            "security_through_obscurity", "insecure_deserialization", "broken_anti_automation",
            "observability_failures", "xxe", "miscellaneous"]
        {
            assert!(ids.contains(expected), "missing family {expected}");
        }
        for f in &fams {
            assert!(!f.questions.is_empty(), "family {} has no questions", f.id);
            assert!(!f.relevant_capabilities.is_empty(), "family {} has no caps", f.id);
        }
    }
}
