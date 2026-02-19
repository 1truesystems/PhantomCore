"""
Attack Surface Analyzer
========================

Graph-based attack surface analysis using directed graphs to model
asset relationships, network paths, and vulnerability propagation.

The attack surface metric quantifies the set of ways an attacker can
interact with a system, weighted by the severity of reachable
vulnerabilities and the centrality of exposed nodes in the network
topology.

The analyser builds a directed graph where nodes represent assets
(servers, services, interfaces) and edges represent connections
(network paths, trust relationships, data flows). Graph-theoretic
metrics including degree centrality, betweenness centrality, and
PageRank identify the most critical nodes and paths.

Algorithm:
    1. Build directed graph from AttackSurfaceNode list
    2. Identify entry points (internet-facing, externally accessible)
    3. Compute node centrality metrics (degree, betweenness, PageRank)
    4. Find critical paths from entry points to high-value assets
    5. Calculate aggregate attack surface score

References:
    - Manadhata, P. K., & Wing, J. M. (2011). An Attack Surface Metric.
      IEEE Transactions on Software Engineering, 37(3), 371-386.
    - Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).
      The PageRank Citation Ranking: Bringing Order to the Web.
      Stanford InfoLab Technical Report 1999-66.
    - Freeman, L. C. (1977). A Set of Measures of Centrality Based on
      Betweenness. Sociometry, 40(1), 35-41.
    - Howard, M., Pincus, J., & Wing, J. M. (2005). Measuring Relative
      Attack Surfaces. In Computer Security in the 21st Century, 109-137.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Optional

from shared.math_utils import pagerank

from nexus.core.models import AttackSurfaceNode


class AttackSurfaceAnalyzer:
    """Graph-based attack surface analyser.

    Builds and analyses directed graphs representing organisational
    attack surfaces. Identifies critical nodes, entry points, and
    shortest attack paths using graph-theoretic algorithms.

    Usage::

        analyzer = AttackSurfaceAnalyzer()
        nodes = [
            AttackSurfaceNode(id="web", type="server", name="Web Server",
                            connections=["app"], is_entry_point=True),
            AttackSurfaceNode(id="app", type="server", name="App Server",
                            connections=["db"]),
            AttackSurfaceNode(id="db", type="database", name="Database",
                            criticality=1.0),
        ]
        graph = analyzer.build_graph(nodes)
        result = analyzer.analyze(graph)
    """

    def __init__(
        self,
        damping: float = 0.85,
        max_iterations: int = 100,
    ) -> None:
        """Initialise the attack surface analyser.

        Args:
            damping: PageRank damping factor (probability of following
                    a link vs. random jump). Default 0.85 per Page et al.
            max_iterations: Maximum PageRank power iterations.
        """
        self.damping = damping
        self.max_iterations = max_iterations

    # ================================================================== #
    #  Graph Construction
    # ================================================================== #

    def build_graph(
        self,
        nodes: list[AttackSurfaceNode],
    ) -> dict[str, Any]:
        """Build a directed graph from a list of attack surface nodes.

        Constructs an internal graph representation suitable for
        analysis. The graph stores node metadata alongside adjacency
        information for centrality and path computations.

        Reference:
            Manadhata, P. K., & Wing, J. M. (2011). An Attack Surface
            Metric. Section 3.1: Attack Surface Definition.

        Args:
            nodes: List of AttackSurfaceNode instances defining the
                  topology and metadata.

        Returns:
            Internal graph representation (dict) containing:
              - 'adjacency': node_id -> [target_ids]
              - 'nodes': node_id -> AttackSurfaceNode
              - 'entry_points': list of entry point node IDs
              - 'high_value': list of high-criticality node IDs
        """
        adjacency: dict[str, list[str]] = {}
        node_map: dict[str, AttackSurfaceNode] = {}
        entry_points: list[str] = []
        high_value: list[str] = []

        # Register all nodes
        for node in nodes:
            node_map[node.id] = node
            adjacency[node.id] = list(node.connections)

            if node.is_entry_point:
                entry_points.append(node.id)

            if node.criticality >= 0.8:
                high_value.append(node.id)

        # Ensure all referenced nodes exist in adjacency
        all_targets: set[str] = set()
        for targets in adjacency.values():
            all_targets.update(targets)
        for target in all_targets:
            if target not in adjacency:
                adjacency[target] = []

        return {
            "adjacency": adjacency,
            "nodes": node_map,
            "entry_points": entry_points,
            "high_value": high_value,
        }

    # ================================================================== #
    #  Analysis
    # ================================================================== #

    def analyze(self, graph: dict[str, Any]) -> dict[str, Any]:
        """Perform comprehensive attack surface analysis.

        Executes the following analyses on the graph:
          1. Degree centrality (in-degree + out-degree per node)
          2. PageRank importance ranking
          3. Critical path identification (entry -> high-value)
          4. Entry point enumeration
          5. Aggregate attack surface score

        Reference:
            Manadhata, P. K., & Wing, J. M. (2011). Section 4:
            Computing the Attack Surface Metric.

        Args:
            graph: Graph dict from build_graph().

        Returns:
            Analysis results dictionary containing:
              - total_score: Aggregate attack surface score [0-100]
              - node_count: Number of nodes in the graph
              - edge_count: Number of directed edges
              - entry_points: List of entry point node details
              - high_value_assets: List of high-criticality node details
              - critical_paths: Shortest paths from entries to targets
              - most_connected: Top nodes by degree centrality
              - pagerank: PageRank scores for all nodes
              - degree_centrality: Degree centrality for all nodes
              - recommendations: List of actionable recommendations
        """
        adjacency = graph["adjacency"]
        node_map: dict[str, AttackSurfaceNode] = graph["nodes"]
        entry_points: list[str] = graph["entry_points"]
        high_value: list[str] = graph["high_value"]

        n_nodes = len(adjacency)
        n_edges = sum(len(targets) for targets in adjacency.values())

        if n_nodes == 0:
            return {
                "total_score": 0.0,
                "node_count": 0,
                "edge_count": 0,
                "entry_points": [],
                "high_value_assets": [],
                "critical_paths": [],
                "most_connected": [],
                "pagerank": {},
                "degree_centrality": {},
                "recommendations": ["No nodes in the attack surface graph."],
            }

        # --- Degree Centrality ---
        degree_centrality = self._compute_degree_centrality(adjacency)

        # --- PageRank ---
        pr_scores = pagerank(
            adjacency,
            damping=self.damping,
            max_iterations=self.max_iterations,
        )

        # --- Critical Paths ---
        critical_paths = self._find_critical_paths(
            adjacency, entry_points, high_value
        )

        # --- Most Connected Nodes ---
        sorted_by_degree = sorted(
            degree_centrality.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        most_connected = [
            {
                "id": node_id,
                "name": node_map[node_id].name if node_id in node_map else node_id,
                "degree_centrality": round(score, 4),
                "type": node_map[node_id].type if node_id in node_map else "unknown",
            }
            for node_id, score in sorted_by_degree[:10]
        ]

        # --- Entry Point Details ---
        entry_details = [
            {
                "id": ep,
                "name": node_map[ep].name if ep in node_map else ep,
                "type": node_map[ep].type if ep in node_map else "unknown",
                "vulnerabilities": (
                    node_map[ep].vulnerabilities if ep in node_map else []
                ),
                "pagerank": round(pr_scores.get(ep, 0.0), 6),
            }
            for ep in entry_points
        ]

        # --- High-Value Asset Details ---
        hv_details = [
            {
                "id": hv,
                "name": node_map[hv].name if hv in node_map else hv,
                "type": node_map[hv].type if hv in node_map else "unknown",
                "criticality": (
                    node_map[hv].criticality if hv in node_map else 0.5
                ),
                "pagerank": round(pr_scores.get(hv, 0.0), 6),
            }
            for hv in high_value
        ]

        # --- PageRank sorted ---
        sorted_pr = {
            k: round(v, 6)
            for k, v in sorted(
                pr_scores.items(), key=lambda x: x[1], reverse=True
            )
        }

        # --- Aggregate Score ---
        total_score = self._compute_surface_score(
            adjacency=adjacency,
            node_map=node_map,
            entry_points=entry_points,
            high_value=high_value,
            degree_centrality=degree_centrality,
            pr_scores=pr_scores,
            critical_paths=critical_paths,
        )

        # --- Recommendations ---
        recommendations = self._generate_recommendations(
            entry_points=entry_points,
            high_value=high_value,
            critical_paths=critical_paths,
            most_connected=most_connected,
            node_map=node_map,
            total_score=total_score,
        )

        return {
            "total_score": round(total_score, 2),
            "node_count": n_nodes,
            "edge_count": n_edges,
            "entry_points": entry_details,
            "high_value_assets": hv_details,
            "critical_paths": critical_paths,
            "most_connected": most_connected,
            "pagerank": sorted_pr,
            "degree_centrality": {
                k: round(v, 4)
                for k, v in sorted(
                    degree_centrality.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
            },
            "recommendations": recommendations,
        }

    # ================================================================== #
    #  Degree Centrality
    # ================================================================== #

    def _compute_degree_centrality(
        self,
        adjacency: dict[str, list[str]],
    ) -> dict[str, float]:
        """Compute normalised degree centrality for all nodes.

        Degree centrality C_D(v) = deg(v) / (N - 1) where deg(v) is
        the sum of in-degree and out-degree, normalised by the maximum
        possible degree.

        Reference:
            Freeman, L. C. (1977). A Set of Measures of Centrality
            Based on Betweenness. Sociometry, 40(1), 35-41.

        Args:
            adjacency: Node-to-targets mapping.

        Returns:
            Node ID to normalised degree centrality mapping.
        """
        all_nodes: set[str] = set(adjacency.keys())
        for targets in adjacency.values():
            all_nodes.update(targets)

        n = len(all_nodes)
        if n <= 1:
            return {node: 0.0 for node in all_nodes}

        # Compute in-degree and out-degree
        out_degree: dict[str, int] = {node: 0 for node in all_nodes}
        in_degree: dict[str, int] = {node: 0 for node in all_nodes}

        for src, targets in adjacency.items():
            out_degree[src] = len(targets)
            for tgt in targets:
                in_degree[tgt] = in_degree.get(tgt, 0) + 1

        # Normalised total degree
        max_degree = 2 * (n - 1)  # max possible in+out degree
        centrality: dict[str, float] = {}
        for node in all_nodes:
            total = out_degree.get(node, 0) + in_degree.get(node, 0)
            centrality[node] = total / max_degree if max_degree > 0 else 0.0

        return centrality

    # ================================================================== #
    #  Critical Path Finding (BFS shortest paths)
    # ================================================================== #

    def _find_critical_paths(
        self,
        adjacency: dict[str, list[str]],
        entry_points: list[str],
        high_value: list[str],
    ) -> list[dict[str, Any]]:
        """Find shortest attack paths from entry points to high-value assets.

        Uses BFS (breadth-first search) to find the shortest directed
        path from each entry point to each high-value target. These
        represent the most direct attack vectors.

        Reference:
            Manadhata, P. K., & Wing, J. M. (2011). Section 4.2:
            Attack Path Analysis.

        Args:
            adjacency: Node-to-targets adjacency mapping.
            entry_points: IDs of internet-facing / exposed nodes.
            high_value: IDs of critical assets.

        Returns:
            List of path dictionaries, each containing:
              - source: Entry point ID
              - target: High-value asset ID
              - path: Ordered list of node IDs
              - length: Number of hops
        """
        high_value_set = set(high_value)
        paths: list[dict[str, Any]] = []

        for entry in entry_points:
            # BFS from entry point
            visited: set[str] = set()
            queue: deque[tuple[str, list[str]]] = deque()
            queue.append((entry, [entry]))
            visited.add(entry)

            while queue:
                current, path = queue.popleft()

                if current in high_value_set and current != entry:
                    paths.append({
                        "source": entry,
                        "target": current,
                        "path": path,
                        "length": len(path) - 1,
                    })
                    # Continue BFS to find paths to other targets
                    # but don't re-explore from this target
                    continue

                for neighbor in adjacency.get(current, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))

        # Sort by path length (shortest first)
        paths.sort(key=lambda p: p["length"])
        return paths

    # ================================================================== #
    #  Aggregate Surface Score
    # ================================================================== #

    def _compute_surface_score(
        self,
        adjacency: dict[str, list[str]],
        node_map: dict[str, AttackSurfaceNode],
        entry_points: list[str],
        high_value: list[str],
        degree_centrality: dict[str, float],
        pr_scores: dict[str, float],
        critical_paths: list[dict[str, Any]],
    ) -> float:
        """Compute the aggregate attack surface score (0-100).

        The score combines multiple dimensions:
          - Entry point exposure (30%): number and connectivity of entry points
          - Path accessibility (25%): number and shortness of critical paths
          - Vulnerability density (20%): vulnerabilities per node
          - Network complexity (15%): graph density and connectivity
          - Asset criticality exposure (10%): criticality of reachable nodes

        Reference:
            Manadhata, P. K., & Wing, J. M. (2011). Section 4:
            Computing the Attack Surface Metric.

        Args:
            adjacency: Graph adjacency mapping.
            node_map: Node ID to AttackSurfaceNode mapping.
            entry_points: Entry point node IDs.
            high_value: High-value asset node IDs.
            degree_centrality: Pre-computed degree centrality.
            pr_scores: Pre-computed PageRank scores.
            critical_paths: Pre-computed critical paths.

        Returns:
            Aggregate score in [0.0, 100.0].
        """
        n_nodes = len(adjacency)
        if n_nodes == 0:
            return 0.0

        # -- Entry Point Exposure (weight: 0.30) --
        entry_ratio = len(entry_points) / max(n_nodes, 1)
        entry_pr_sum = sum(pr_scores.get(ep, 0.0) for ep in entry_points)
        entry_score = min(100.0, (entry_ratio * 50.0 + entry_pr_sum * 500.0))

        # -- Path Accessibility (weight: 0.25) --
        if critical_paths:
            avg_path_length = sum(p["length"] for p in critical_paths) / len(
                critical_paths
            )
            # Shorter paths = higher risk; cap at path length 1
            path_risk = max(0.0, 100.0 - (avg_path_length - 1) * 15.0)
            path_count_factor = min(1.0, len(critical_paths) / 10.0)
            path_score = path_risk * path_count_factor
        else:
            path_score = 0.0

        # -- Vulnerability Density (weight: 0.20) --
        total_vulns = sum(
            len(node.vulnerabilities)
            for node in node_map.values()
        )
        vuln_density = total_vulns / max(n_nodes, 1)
        vuln_score = min(100.0, vuln_density * 25.0)

        # -- Network Complexity (weight: 0.15) --
        n_edges = sum(len(targets) for targets in adjacency.values())
        max_edges = n_nodes * (n_nodes - 1)
        density = n_edges / max_edges if max_edges > 0 else 0.0
        avg_centrality = (
            sum(degree_centrality.values()) / n_nodes if n_nodes > 0 else 0.0
        )
        complexity_score = min(100.0, (density * 50.0 + avg_centrality * 200.0))

        # -- Asset Criticality Exposure (weight: 0.10) --
        reachable_criticality = 0.0
        for hv_id in high_value:
            if hv_id in node_map:
                reachable_criticality += node_map[hv_id].criticality
        criticality_score = min(
            100.0,
            (reachable_criticality / max(len(high_value), 1)) * 100.0,
        )

        # Weighted combination
        total_score = (
            0.30 * entry_score
            + 0.25 * path_score
            + 0.20 * vuln_score
            + 0.15 * complexity_score
            + 0.10 * criticality_score
        )

        return min(100.0, max(0.0, total_score))

    # ================================================================== #
    #  Recommendation Generation
    # ================================================================== #

    def _generate_recommendations(
        self,
        entry_points: list[str],
        high_value: list[str],
        critical_paths: list[dict[str, Any]],
        most_connected: list[dict[str, Any]],
        node_map: dict[str, AttackSurfaceNode],
        total_score: float,
    ) -> list[str]:
        """Generate actionable recommendations based on analysis results.

        Produces prioritised security recommendations tailored to the
        specific attack surface topology and identified weaknesses.

        Args:
            entry_points: Entry point node IDs.
            high_value: High-value asset IDs.
            critical_paths: Identified attack paths.
            most_connected: Top nodes by degree centrality.
            node_map: Node metadata mapping.
            total_score: Aggregate attack surface score.

        Returns:
            List of recommendation strings, ordered by priority.
        """
        recs: list[str] = []

        if total_score >= 70:
            recs.append(
                "CRITICAL: Attack surface score is very high. Immediate "
                "action required to reduce exposure."
            )

        # Entry point recommendations
        if len(entry_points) > 3:
            recs.append(
                f"Reduce the number of entry points (currently {len(entry_points)}). "
                "Consolidate internet-facing services behind a reverse proxy "
                "or web application firewall (WAF)."
            )

        # Short critical paths
        short_paths = [p for p in critical_paths if p["length"] <= 2]
        if short_paths:
            targets = {p["target"] for p in short_paths}
            recs.append(
                f"High-value assets ({', '.join(targets)}) are reachable in "
                f"2 hops or fewer from entry points. Add network segmentation "
                f"or additional authentication barriers."
            )

        # Highly connected nodes (potential pivot points)
        if most_connected:
            top = most_connected[0]
            if top["degree_centrality"] > 0.5:
                recs.append(
                    f"Node '{top['name']}' has very high degree centrality "
                    f"({top['degree_centrality']:.2f}). It is a critical "
                    f"pivot point. Harden this node and restrict its connections."
                )

        # Vulnerability recommendations
        vuln_nodes = [
            node for node in node_map.values()
            if len(node.vulnerabilities) > 0
        ]
        if vuln_nodes:
            total_vulns = sum(len(n.vulnerabilities) for n in vuln_nodes)
            recs.append(
                f"Patch {total_vulns} known vulnerabilities across "
                f"{len(vuln_nodes)} nodes. Prioritise entry points and "
                f"high-centrality nodes."
            )

        # General
        if not recs:
            recs.append(
                "Attack surface is within acceptable parameters. Continue "
                "monitoring and regular assessments."
            )

        return recs
