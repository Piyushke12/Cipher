//! TargetModel: structured representation of what has been discovered.
//!
//! Generic — no application-specific endpoints, fingerprints, or attack
//! paths. Different tools reporting the same entity converge via stable
//! normalized identifiers, not human-readable summary strings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Normalize a host for identity: lowercase, strip scheme/userinfo/port/path.
pub fn normalize_host(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
            break;
        }
    }
    if let Some(at) = s.rfind('@') {
        s = s[at + 1..].to_string();
    }
    // Strip path/query/fragment.
    for sep in ['/', '?', '#'] {
        if let Some(idx) = s.find(sep) {
            s.truncate(idx);
            break;
        }
    }
    // Strip port (but keep IPv6 `[::1]` intact).
    if !s.ends_with(']') {
        if let Some(colon) = s.rfind(':') {
            let after = &s[colon + 1..];
            if after.chars().all(|c| c.is_ascii_digit()) {
                s.truncate(colon);
            }
        }
    }
    // Strip IPv6 brackets.
    if s.starts_with('[') && s.ends_with(']') && s.len() > 2 {
        s = s[1..s.len() - 1].to_string();
    }
    s.trim_end_matches('.').to_string()
}

/// Stable host entity id.
pub fn host_id(raw: &str) -> String {
    format!("host:{}", normalize_host(raw))
}

/// Stable host:port id.
pub fn port_id(host_raw: &str, port: u16, protocol: &str) -> String {
    format!(
        "hostport:{}:{}/{}",
        normalize_host(host_raw),
        port,
        protocol.to_lowercase()
    )
}

/// Normalize a URL into a stable endpoint id (lowercase scheme/host,
/// drop default ports, drop trailing slash except root, drop fragment).
/// Path case is preserved: paths may be case-sensitive.
pub fn endpoint_id(url_raw: &str) -> String {
    let mut s = url_raw.trim().to_string();
    // Drop fragment.
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }
    // Split scheme (case-insensitive).
    let (scheme_raw, rest_raw) = match s.find("://") {
        Some(i) => (s[..i].to_string(), s[i + 3..].to_string()),
        None => ("http".to_string(), s.clone()),
    };
    let scheme = scheme_raw.to_lowercase();
    // Split host[:port] from path (preserve path case).
    let (hostport_raw, path) = match rest_raw.find('/') {
        Some(i) => (rest_raw[..i].to_string(), rest_raw[i..].to_string()),
        None => (rest_raw.clone(), "/".to_string()),
    };
    let mut hostport = hostport_raw.to_lowercase();
    if (scheme == "http" && hostport.ends_with(":80"))
        || (scheme == "https" && hostport.ends_with(":443"))
    {
        let cut = hostport.rfind(':').unwrap();
        hostport.truncate(cut);
    }
    let mut path = path;
    if path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    format!("endpoint:{scheme}://{hostport}{path}")
}

/// Stable parameter id: endpoint + location + lowercase name.
pub fn param_id(endpoint_url: &str, location: &str, name: &str) -> String {
    format!(
        "param:{}:{}:{}",
        endpoint_id(endpoint_url),
        location.to_lowercase(),
        name.to_lowercase()
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub host: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub id: String,
    pub host_id: String,
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub url: String,
    pub host_id: String,
    pub technologies: Vec<String>,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    pub id: String,
    pub endpoint_id: String,
    pub name: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub role: String,
    pub privilege: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    pub owner_identity: Option<String>,
    pub requires_privilege: Option<String>,
    pub reachable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TargetModel {
    pub hosts: HashMap<String, Host>,
    pub ports: HashMap<String, Port>,
    pub endpoints: HashMap<String, Endpoint>,
    pub params: HashMap<String, Parameter>,
    pub identities: HashMap<String, Identity>,
    pub resources: HashMap<String, Resource>,
    /// Current operative identity, if any (e.g. `authenticated:user`).
    #[serde(default)]
    pub current_identity: Option<String>,
}

impl TargetModel {
    pub fn upsert_host(&mut self, raw_host: &str, source: &str) -> String {
        let id = host_id(raw_host);
        let norm = normalize_host(raw_host);
        self.hosts
            .entry(id.clone())
            .and_modify(|h| {
                if !h.sources.contains(&source.to_string()) {
                    h.sources.push(source.to_string());
                }
            })
            .or_insert(Host {
                id: id.clone(),
                host: norm,
                sources: vec![source.to_string()],
            });
        id
    }

    pub fn upsert_port(
        &mut self,
        host_raw: &str,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<&str>,
        version: Option<&str>,
    ) -> String {
        let hid = self.upsert_host(host_raw, "port");
        let id = port_id(host_raw, port, protocol);
        self.ports
            .entry(id.clone())
            .and_modify(|p| {
                if p.state == "unknown" && !state.is_empty() {
                    p.state = state.to_string();
                }
                if p.service.is_none() {
                    p.service = service.map(str::to_string);
                }
                if p.version.is_none() {
                    p.version = version.map(str::to_string);
                }
            })
            .or_insert(Port {
                id: id.clone(),
                host_id: hid,
                number: port,
                protocol: protocol.to_lowercase(),
                state: state.to_string(),
                service: service.map(str::to_string),
                version: version.map(str::to_string),
            });
        id
    }

    pub fn upsert_endpoint(
        &mut self,
        url: &str,
        status: Option<u16>,
        tech: &[String],
    ) -> String {
        let id = endpoint_id(url);
        let host_part = normalize_host(url);
        let hid = self.upsert_host(&host_part, "endpoint");
        self.endpoints
            .entry(id.clone())
            .and_modify(|e| {
                if e.status.is_none() {
                    e.status = status;
                }
                for t in tech {
                    if !e.technologies.contains(t) {
                        e.technologies.push(t.clone());
                    }
                }
            })
            .or_insert(Endpoint {
                id: id.clone(),
                url: url.to_string(),
                host_id: hid,
                technologies: tech.to_vec(),
                status,
            });
        id
    }

    pub fn upsert_param(&mut self, endpoint_url: &str, name: &str, location: &str) -> String {
        let eid = self.upsert_endpoint(endpoint_url, None, &[]);
        let id = param_id(endpoint_url, location, name);
        self.params.entry(id.clone()).or_insert(Parameter {
            id: id.clone(),
            endpoint_id: eid,
            name: name.to_string(),
            location: location.to_lowercase(),
        });
        id
    }

    pub fn upsert_identity(&mut self, name: &str, role: &str, privilege: &str) -> String {
        let id = format!("identity:{}", name.to_lowercase());
        self.identities.entry(id.clone()).or_insert(Identity {
            id: id.clone(),
            name: name.to_string(),
            role: role.to_string(),
            privilege: privilege.to_string(),
        });
        id
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.hosts.len(),
            self.ports.len(),
            self.endpoints.len(),
            self.params.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_host_converges_across_forms() {
        let mut m = TargetModel::default();
        let a = m.upsert_host("https://Example.com:443/a?x=1", "nmap");
        let b = m.upsert_host("example.com", "httpx");
        assert_eq!(a, b);
        assert_eq!(m.hosts.len(), 1);
        assert_eq!(m.hosts[&a].sources.len(), 2);
    }

    #[test]
    fn same_endpoint_converges_crawler_vs_api_discovery() {
        let mut m = TargetModel::default();
        let a = m.upsert_endpoint("https://EXAMPLE.com:443/api/users/", Some(200), &[]);
        let b = m.upsert_endpoint("https://example.com/api/users", Some(200), &[]);
        // Host case + default port + trailing slash converge; path case is
        // preserved (may be significant):
        assert_eq!(a, b);
        let c = m.upsert_endpoint("https://example.com/API/Users", Some(200), &[]);
        assert_ne!(a, c); // documents case-sensitivity decision
        assert_eq!(m.hosts.len(), 1);
    }

    #[test]
    fn same_param_converges_across_tools() {
        let mut m = TargetModel::default();
        let a = m.upsert_param("http://example.com/search", "Q", "query");
        let b = m.upsert_param("http://example.com/search", "q", "QUERY");
        assert_eq!(a, b);
        assert_eq!(m.params.len(), 1);
    }

    #[test]
    fn port_merge_prefers_known_service() {
        let mut m = TargetModel::default();
        m.upsert_port("10.0.0.1", 80, "tcp", "open", None, None);
        m.upsert_port("10.0.0.1", 80, "TCP", "open", Some("http"), Some("2.4"));
        let p = &m.ports[&port_id("10.0.0.1", 80, "tcp")];
        assert_eq!(p.service.as_deref(), Some("http"));
    }
}
