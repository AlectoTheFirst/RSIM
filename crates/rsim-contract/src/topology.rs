//! The topology of a twin for a drawing: nodes and edges at one level,
//! with the layers of the edges, and the paths of a query answer drawn on
//! it. The exports to Mermaid, D2 and GraphML are for small views.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::ClaimResult;
use crate::twin::TwinJson;

/// One node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TopoNode {
    pub id: String,
    /// `device` or `function`.
    pub kind: String,
    pub label: String,
    pub device: Option<String>,
    /// The number of functions of a device node.
    pub functions: Option<usize>,
}

/// One edge.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TopoEdge {
    pub id: String,
    /// `physical`, `overlay` or `function`; in a path drawing also
    /// `underlay` for a hop of an encapsulated packet.
    pub layer: String,
    pub from: String,
    pub to: String,
    /// The facts of the edge, for example the speed and the duplex of both
    /// ends of a link, or the tunnels of an overlay edge, each with its
    /// encapsulation function, its source, its peer and its VNIs.
    pub facts: Value,
    /// The source spans of the facts: file:first-last.
    pub provenance: Vec<String>,
    /// The result of each requested claim on the edge.
    pub claims: BTreeMap<String, ClaimResult>,
    /// In a path drawing: the branches that cross the edge.
    pub branches: Vec<usize>,
    /// In a path drawing: the overlay edge of an underlay edge.
    pub overlay: Option<String>,
}

/// The topology of a twin, or the drawing of the paths of a query.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct TopologyOut {
    pub rsim_json: u32,
    pub kind: String,
    pub topology: String,
    pub twin: TwinJson,
    /// `device` or `function`.
    pub level: String,
    pub layers: Vec<String>,
    pub nodes: Vec<TopoNode>,
    pub edges: Vec<TopoEdge>,
}

fn safe(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

impl TopologyOut {
    /// A Mermaid flowchart.
    pub fn mermaid(&self) -> String {
        let mut t = String::from("graph LR\n");
        for n in &self.nodes {
            t.push_str(&format!(
                "  {}[\"{}\"]\n",
                safe(&n.id),
                n.label.replace('"', "'")
            ));
        }
        for e in &self.edges {
            let arrow = match e.layer.as_str() {
                "overlay" => "-.->",
                "function" => "-->",
                _ => "---",
            };
            t.push_str(&format!("  {} {arrow} {}\n", safe(&e.from), safe(&e.to)));
        }
        t
    }

    /// A D2 diagram.
    pub fn d2(&self) -> String {
        let mut t = String::new();
        for n in &self.nodes {
            t.push_str(&format!(
                "{}: \"{}\"\n",
                safe(&n.id),
                n.label.replace('"', "'")
            ));
        }
        for e in &self.edges {
            let arrow = if e.layer == "function" { "->" } else { "--" };
            t.push_str(&format!(
                "{} {arrow} {}: {}\n",
                safe(&e.from),
                safe(&e.to),
                e.layer
            ));
        }
        t
    }

    /// A GraphML document.
    pub fn graphml(&self) -> String {
        let mut t = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n  <key id=\"layer\" for=\"edge\" attr.name=\"layer\" attr.type=\"string\"/>\n  <graph id=\"rsim\" edgedefault=\"undirected\">\n",
        );
        for n in &self.nodes {
            t.push_str(&format!(
                "    <node id=\"{}\"><data key=\"label\">{}</data></node>\n",
                escape_xml(&n.id),
                escape_xml(&n.label)
            ));
        }
        for e in &self.edges {
            t.push_str(&format!(
                "    <edge id=\"{}\" source=\"{}\" target=\"{}\"><data key=\"layer\">{}</data></edge>\n",
                escape_xml(&e.id),
                escape_xml(&e.from),
                escape_xml(&e.to),
                escape_xml(&e.layer)
            ));
        }
        t.push_str("  </graph>\n</graphml>\n");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> TopologyOut {
        let node = |id: &str| TopoNode {
            id: id.into(),
            kind: "device".into(),
            label: id.into(),
            device: Some(id.into()),
            functions: Some(1),
        };
        TopologyOut {
            rsim_json: 2,
            kind: "topology".into(),
            topology: "t".into(),
            twin: TwinJson::builtin("t").unwrap(),
            level: "device".into(),
            layers: vec!["physical".into()],
            nodes: vec![node("r1"), node("r-2")],
            edges: vec![TopoEdge {
                id: "e0".into(),
                layer: "physical".into(),
                from: "r1".into(),
                to: "r-2".into(),
                facts: Value::Null,
                provenance: Vec::new(),
                claims: BTreeMap::new(),
                branches: Vec::new(),
                overlay: None,
            }],
        }
    }

    #[test]
    fn the_exports_name_each_node_and_edge() {
        let t = small();
        assert!(t.mermaid().contains("r1 --- r_2"));
        assert!(t.d2().contains("r1 -- r_2: physical"));
        let g = t.graphml();
        assert!(g.contains("<edge id=\"e0\" source=\"r1\" target=\"r-2\">"));
        assert_eq!(g.matches("<node ").count(), 2);
    }
}
