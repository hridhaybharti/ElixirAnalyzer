from __future__ import annotations

from typing import Dict, List, Set, Tuple


class _Node:
    def __init__(self, node_type: str, identifier: str, attributes=None):
        self.node_type = node_type
        self.identifier = identifier
        self.attributes = dict(attributes or {})


class InfrastructureGraph:
    def __init__(self):
        self._nodes: Dict[Tuple[str, str], _Node] = {}
        self._edges: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}

    def add_node(self, node_type: str, identifier: str, attributes=None) -> _Node:
        key = (node_type, identifier)
        if key not in self._nodes:
            self._nodes[key] = _Node(node_type, identifier, attributes)
        else:
            if attributes:
                self._nodes[key].attributes.update(attributes)
        return self._nodes[key]

    def add_edge(self, src_type: str, src_id: str, dst_type: str, dst_id: str) -> None:
        a = (src_type, src_id)
        b = (dst_type, dst_id)
        # Ensure nodes exist
        if a not in self._nodes:
            self.add_node(src_type, src_id, {})
        if b not in self._nodes:
            self.add_node(dst_type, dst_id, {})
        if a not in self._edges:
            self._edges[a] = set()
        if b not in self._edges:
            self._edges[b] = set()
        self._edges[a].add(b)
        self._edges[b].add(a)

    def get_nodes_by_type(self, node_type: str) -> List[_Node]:
        return [n for (t, _), n in self._nodes.items() if t == node_type]

    def get_neighbors(self, node_type: str, identifier: str) -> List[_Node]:
        key = (node_type, identifier)
        neighbors = []
        for nb in self._edges.get(key, []):
            neigh = self._nodes.get(nb)
            if neigh:
                neighbors.append(neigh)
        return neighbors

    def get_all_nodes(self) -> List[_Node]:
        return list(self._nodes.values())

    def find_cluster(self, node_type: str, identifier: str) -> Dict[str, int]:
        # BFS to count reachable nodes from starting node
        start = (node_type, identifier)
        if start not in self._edges:
            return {"cluster_size": 1}
        visited = set()
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            for nb in self._edges.get(cur, []):
                if nb not in visited:
                    stack.append(nb)
        return {"cluster_size": len(visited)}

    def detect_suspicious_clusters(self) -> List[Dict[str, int]]:
        clusters = []
        # naive: any IP node connected to 2+ domain nodes
        for (t, ident), neighs in self._edges.items():
            if t == "ip":
                domain_count = sum(1 for nb in neighs if self._nodes.get(nb) and self._nodes[nb].node_type == "domain")
                if domain_count >= 2:
                    clusters.append({"cluster_size": domain_count + 1})
        return clusters

    def export_json(self) -> Dict[str, object]:
        total = len(self._nodes)
        by_type: Dict[str, List[Dict[str, object]]] = {}
        for (t, ident), node in self._nodes.items():
            by_type.setdefault(t, []).append({"identifier": ident, "attributes": dict(node.attributes)})
        return {"total_nodes": total, "nodes_by_type": by_type}


class GraphAnalyzer:
    def __init__(self):
        self.graph = InfrastructureGraph()

    def add_domain_analysis(self, domain: str, risk_score: int, associated_ips: List[str]) -> None:
        self.graph.add_node("domain", domain, {"risk_score": risk_score})
        for ip in associated_ips:
            self.graph.add_node("ip", ip, {})
            self.graph.add_edge("domain", domain, "ip", ip)

    def add_ip_analysis(self, ip: str, risk_score: int, asn: str) -> None:
        self.graph.add_node("ip", ip, {"risk_score": risk_score, "asn": asn})

    def get_infrastructure_context(self, node_type: str, identifier: str) -> Dict[str, object]:
        cluster = self.graph.find_cluster(node_type, identifier)
        return {
            "target": {"type": node_type, "identifier": identifier},
            "cluster": cluster,
        }
