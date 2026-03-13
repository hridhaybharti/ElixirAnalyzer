"""Graph-Based Infrastructure Analysis.

Track relationships between domains, IPs, ASNs, and hosting providers.
Detect suspicious clusters.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("graph_analysis")


class InfrastructureNode:
    """Represents a node in the infrastructure graph."""

    def __init__(self, node_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Args:
            node_type: "domain", "ip", "asn", "provider"
            identifier: unique identifier (domain name, IP address, ASN number, provider name)
            metadata: optional metadata about the node
        """
        self.node_type = node_type
        self.identifier = identifier
        self.metadata = metadata or {}
        self.connected: List[InfrastructureNode] = []

    def add_connection(self, other: InfrastructureNode) -> None:
        """Add a connection to another node."""
        if other not in self.connected:
            self.connected.append(other)

    def __repr__(self) -> str:
        return f"InfrastructureNode({self.node_type}, {self.identifier})"


class InfrastructureGraph:
    """Graph representation of infrastructure relationships."""

    def __init__(self):
        self.nodes: Dict[str, InfrastructureNode] = {}

    def add_node(self, node_type: str, identifier: str, metadata: Optional[Dict[str, Any]] = None) -> InfrastructureNode:
        """Add or retrieve a node."""
        key = f"{node_type}:{identifier}"
        if key not in self.nodes:
            self.nodes[key] = InfrastructureNode(node_type, identifier, metadata)
        return self.nodes[key]

    def add_edge(self, node_type_a: str, identifier_a: str, node_type_b: str, identifier_b: str) -> None:
        """Add a bidirectional edge between two nodes."""
        node_a = self.add_node(node_type_a, identifier_a)
        node_b = self.add_node(node_type_b, identifier_b)
        node_a.add_connection(node_b)
        node_b.add_connection(node_a)

    def get_nodes_by_type(self, node_type: str) -> List[InfrastructureNode]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_neighbors(self, node_type: str, identifier: str) -> List[InfrastructureNode]:
        """Get all neighbors of a node."""
        key = f"{node_type}:{identifier}"
        if key not in self.nodes:
            return []
        return self.nodes[key].connected

    def find_cluster(self, node_type: str, identifier: str, max_depth: int = 3) -> Dict[str, Any]:
        """Find a cluster of related infrastructure around a node."""
        key = f"{node_type}:{identifier}"
        if key not in self.nodes:
            return {"error": f"Node not found: {key}"}

        visited: Set[str] = set()
        cluster_nodes: Dict[str, List[str]] = {}

        def dfs(current_key: str, depth: int) -> None:
            if depth > max_depth or current_key in visited:
                return
            visited.add(current_key)

            node = self.nodes[current_key]
            if node.node_type not in cluster_nodes:
                cluster_nodes[node.node_type] = []
            cluster_nodes[node.node_type].append(node.identifier)

            for neighbor in node.connected:
                neighbor_key = f"{neighbor.node_type}:{neighbor.identifier}"
                if neighbor_key not in visited:
                    dfs(neighbor_key, depth + 1)

        dfs(key, 0)

        return {
            "root": {"type": node_type, "identifier": identifier},
            "cluster_size": len(visited),
            "nodes_by_type": cluster_nodes,
        }

    def detect_suspicious_clusters(self) -> List[Dict[str, Any]]:
        """Detect suspicious clusters (e.g., multiple malicious domains on one IP)."""
        suspicious_clusters = []

        # Group domains by IP
        ip_nodes = self.get_nodes_by_type("ip")
        for ip_node in ip_nodes:
            connected_domains = [n for n in ip_node.connected if n.node_type == "domain"]

            if len(connected_domains) >= 3:
                # Multiple domains on one IP is suspicious
                malicious_count = sum(
                    1 for d in connected_domains
                    if d.metadata.get("risk_score", 0) > 50
                )
                if malicious_count >= 2:
                    suspicious_clusters.append(
                        {
                            "cluster_type": "multiple_malicious_domains_on_ip",
                            "ip": ip_node.identifier,
                            "total_domains": len(connected_domains),
                            "malicious_domains": malicious_count,
                            "domains": [d.identifier for d in connected_domains],
                        }
                    )

        # Group IPs by ASN
        asn_nodes = self.get_nodes_by_type("asn")
        for asn_node in asn_nodes:
            connected_ips = [n for n in asn_node.connected if n.node_type == "ip"]
            if len(connected_ips) >= 5:
                malicious_ips = sum(1 for ip in connected_ips if ip.metadata.get("risk_score", 0) > 50)
                if malicious_ips >= 3:
                    suspicious_clusters.append(
                        {
                            "cluster_type": "multiple_malicious_ips_in_asn",
                            "asn": asn_node.identifier,
                            "total_ips": len(connected_ips),
                            "malicious_ips": malicious_ips,
                        }
                    )

        return suspicious_clusters

    def export_json(self) -> Dict[str, Any]:
        """Export graph as JSON-serializable dict."""
        nodes_by_type: Dict[str, List[Dict[str, Any]]] = {}

        for node in self.nodes.values():
            if node.node_type not in nodes_by_type:
                nodes_by_type[node.node_type] = []

            nodes_by_type[node.node_type].append(
                {
                    "identifier": node.identifier,
                    "metadata": node.metadata,
                    "connections": [f"{n.node_type}:{n.identifier}" for n in node.connected],
                }
            )

        return {
            "total_nodes": len(self.nodes),
            "nodes_by_type": nodes_by_type,
        }


class GraphAnalyzer:
    """Analyze threat data and build infrastructure graphs."""

    def __init__(self):
        self.graph = InfrastructureGraph()

    def add_domain_analysis(
        self, domain: str, risk_score: int, associated_ips: Optional[List[str]] = None
    ) -> None:
        """Add domain analysis results to the graph."""
        domain_node = self.graph.add_node("domain", domain, {"risk_score": risk_score})

        if associated_ips:
            for ip in associated_ips:
                self.graph.add_edge("domain", domain, "ip", ip)

    def add_ip_analysis(
        self, ip: str, risk_score: int, asn: Optional[str] = None, provider: Optional[str] = None
    ) -> None:
        """Add IP analysis results to the graph."""
        ip_node = self.graph.add_node("ip", ip, {"risk_score": risk_score})

        if asn:
            self.graph.add_edge("ip", ip, "asn", asn)

        if provider:
            self.graph.add_edge("ip", ip, "provider", provider)

    def get_infrastructure_context(self, target_type: str, target_id: str) -> Dict[str, Any]:
        """Get infrastructure context for a target."""
        cluster = self.graph.find_cluster(target_type, target_id)
        suspicious = self.graph.detect_suspicious_clusters()

        return {
            "target": {"type": target_type, "identifier": target_id},
            "cluster": cluster,
            "suspicious_clusters": [
                s for s in suspicious if target_id in str(s)
            ],  # Filter to relevant clusters
            "graph_summary": self.graph.export_json(),
        }


# Global analyzer instance
_analyzer: Optional[GraphAnalyzer] = None


def get_analyzer() -> GraphAnalyzer:
    """Get or create the global graph analyzer."""
    global _analyzer
    if _analyzer is None:
        _analyzer = GraphAnalyzer()
    return _analyzer
