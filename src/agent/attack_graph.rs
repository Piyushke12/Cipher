//! AttackGraph: explicit security-relationship graph.
//!
//! Generic nodes/edges only — no application-specific chains. Derived from
//! evidence and state transitions; the LLM reasons over its projection.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Asset,
    Endpoint,
    Input,
    Weakness,
    Identity,
    Credential,
    Privilege,
    Resource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Exposes,
    Contains,
    Accepts,
    Requires,
    GrantsAccess,
    EscalatesTo,
    Reaches,
    DependsOn,
    ValidatedBy,
    Enables,
    SameIdentityAs,
    Trusts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub step_added: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttackGraph {
    pub nodes: HashMap<String, GraphNode>,
    pub edges: HashSet<GraphEdge>,
}

impl AttackGraph {
    pub fn upsert_node(
        &mut self,
        id: &str,
        kind: NodeKind,
        label: &str,
        step: usize,
    ) -> bool {
        let is_new = !self.nodes.contains_key(id);
        self.nodes.entry(id.to_string()).or_insert(GraphNode {
            id: id.to_string(),
            kind,
            label: label.to_string(),
            step_added: step,
        });
        is_new
    }

    /// Returns true if the edge is new.
    pub fn link(&mut self, from: &str, to: &str, kind: EdgeKind) -> bool {
        self.edges.insert(GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
            kind,
        })
    }

    /// Nodes added after `since_step` (exclusive).
    pub fn newly_reachable(&self, since_step: usize) -> Vec<&GraphNode> {
        let mut v: Vec<&GraphNode> = self
            .nodes
            .values()
            .filter(|n| n.step_added > since_step)
            .collect();
        v.sort_by_key(|n| (n.step_added, n.id.clone()));
        v
    }

    /// BFS path from `from` to `to` following directed edges.
    pub fn path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for e in &self.edges {
            adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
        }
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut q = VecDeque::from([from.to_string()]);
        let mut seen = HashSet::from([from.to_string()]);
        while let Some(cur) = q.pop_front() {
            if cur == to {
                let mut path = vec![to.to_string()];
                let mut c = to.to_string();
                while let Some(p) = prev.get(&c) {
                    path.push(p.clone());
                    c = p.clone();
                }
                path.reverse();
                return Some(path);
            }
            if let Some(nexts) = adj.get(cur.as_str()) {
                for n in nexts {
                    if seen.insert(n.to_string()) {
                        prev.insert(n.to_string(), cur.clone());
                        q.push_back(n.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn privileges(&self) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| n.kind == NodeKind::Privilege || n.kind == NodeKind::Identity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> AttackGraph {
        let mut g = AttackGraph::default();
        g.upsert_node("asset:h", NodeKind::Asset, "h", 1);
        g.upsert_node("ep:login", NodeKind::Endpoint, "login", 1);
        g.upsert_node("weak:sqli", NodeKind::Weakness, "sqli", 2);
        g.upsert_node("id:admin", NodeKind::Identity, "admin", 3);
        g.upsert_node("priv:admin", NodeKind::Privilege, "admin", 3);
        g.upsert_node("res:db", NodeKind::Resource, "db", 4);
        g.link("asset:h", "ep:login", EdgeKind::Exposes);
        g.link("ep:login", "weak:sqli", EdgeKind::Contains);
        g.link("weak:sqli", "id:admin", EdgeKind::GrantsAccess);
        g.link("id:admin", "priv:admin", EdgeKind::EscalatesTo);
        g.link("priv:admin", "res:db", EdgeKind::Reaches);
        g
    }

    #[test]
    fn dedupes_nodes_and_edges() {
        let mut g = AttackGraph::default();
        assert!(g.upsert_node("a", NodeKind::Asset, "a", 1));
        assert!(!g.upsert_node("a", NodeKind::Asset, "a-changed", 2));
        assert_eq!(g.nodes["a"].label, "a"); // first wins
        assert!(g.link("a", "b", EdgeKind::Reaches));
        assert!(!g.link("a", "b", EdgeKind::Reaches));
    }

    #[test]
    fn builds_path_and_newly_reachable() {
        let g = chain();
        let p = g.path("asset:h", "res:db").unwrap();
        assert_eq!(p.first().unwrap(), "asset:h");
        assert_eq!(p.last().unwrap(), "res:db");
        assert!(g.path("res:db", "asset:h").is_none());
        let fresh: Vec<String> =
            g.newly_reachable(2).iter().map(|n| n.id.clone()).collect();
        assert!(fresh.contains(&"id:admin".to_string()));
        assert!(fresh.contains(&"res:db".to_string()));
    }

    #[test]
    fn privilege_transition_visible() {
        let g = chain();
        assert!(!g.privileges().is_empty());
    }
}
