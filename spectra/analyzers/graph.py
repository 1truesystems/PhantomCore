"""
Spectra Graph Analyzer
=======================

Network communication graph analysis using NetworkX. Computes centrality
metrics, community structure, and topological properties of the observed
communication graph to identify key infrastructure nodes, network segments,
and anomalous connectivity patterns.

Centrality Metrics:
    - Betweenness centrality (Freeman, 1977): identifies bridge nodes.
    - Eigenvector centrality: measures influence based on neighbour importance.
    - PageRank (Page et al., 1999): importance ranking via random-surfer model.
    - Degree centrality (in/out): connection count normalisation.

Community Detection:
    - Greedy modularity optimisation (Clauset, Newman, & Moore, 2004),
      related to the Louvain method (Blondel et al., 2008).
    - Modularity Q = (1/2m) * Sum[A_ij - k_i*k_j/(2m)] * delta(c_i, c_j)

References:
    - Freeman, L. C. (1977). A Set of Measures of Centrality Based on
      Betweenness. Sociometry, 40(1), 35-41.
    - Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).
      The PageRank Citation Ranking: Bringing Order to the Web.
      Stanford InfoLab Technical Report 1999-66.
    - Blondel, V. D., Guillaume, J.-L., Lambiotte, R., & Lefebvre, E.
      (2008). Fast unfolding of communities in large networks.
      Journal of Statistical Mechanics, 2008(10), P10008.
    - Clauset, A., Newman, M. E. J., & Moore, C. (2004). Finding
      community structure in very large networks.
      Physical Review E, 70(6), 066111.
    - Newman, M. E. J. (2010). Networks: An Introduction.
      Oxford University Press.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx

from shared.logger import PhantomLogger

from spectra.core.models import (
    CommunicationGraph,
    CommunityResult,
    NetworkFlow,
    NetworkHost,
)

logger = PhantomLogger("spectra.graph")


class GraphAnalyzer:
    """Analyses the communication graph derived from network flows.

    Constructs a weighted directed graph where nodes represent hosts
    and edge weights represent aggregated traffic volume. Computes
    centrality metrics, detects community structure, and identifies
    topological properties.

    Usage::

        analyzer = GraphAnalyzer(top_n=10)
        graph = analyzer.build_graph(hosts, flows)
        analysis = analyzer.analyze(graph)
    """

    def __init__(self, top_n: int = 10) -> None:
        """Initialise the graph analyzer.

        Args:
            top_n: Number of top nodes to report per centrality metric.
        """
        self.top_n: int = top_n

    # ------------------------------------------------------------------ #
    #  Graph Construction
    # ------------------------------------------------------------------ #

    def build_graph(
        self,
        hosts: dict[str, NetworkHost],
        flows: list[NetworkFlow],
    ) -> nx.DiGraph:
        """Build a weighted directed communication graph from hosts and flows.

        Nodes represent hosts with attributes from NetworkHost.
        Edges are aggregated by (src_ip, dst_ip) pair with weights
        equal to total bytes transferred.

        Args:
            hosts: Mapping from IP to NetworkHost.
            flows: List of network flows.

        Returns:
            NetworkX DiGraph with host nodes and weighted edges.
        """
        G = nx.DiGraph()

        # Add nodes with attributes
        for ip, host in hosts.items():
            G.add_node(
                ip,
                mac=host.mac,
                hostname=host.hostname,
                bytes_sent=host.bytes_sent,
                bytes_recv=host.bytes_recv,
                packet_count=host.packet_count,
                port_count=len(host.ports),
            )

        # Aggregate edges by (src, dst) pair
        edge_data: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "bytes_total": 0,
                "packets": 0,
                "protocols": set(),
                "ports": set(),
                "flow_count": 0,
            }
        )

        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)
            ed = edge_data[key]
            ed["bytes_total"] += flow.bytes_total
            ed["packets"] += flow.packets
            ed["protocols"].add(flow.protocol)
            if flow.dst_port > 0:
                ed["ports"].add(flow.dst_port)
            ed["flow_count"] += 1

        # Add edges
        for (src, dst), data in edge_data.items():
            # Ensure both nodes exist
            if src not in G:
                G.add_node(src)
            if dst not in G:
                G.add_node(dst)

            G.add_edge(
                src, dst,
                weight=float(data["bytes_total"]),
                packets=data["packets"],
                protocols=list(data["protocols"]),
                ports=sorted(data["ports"]),
                flow_count=data["flow_count"],
            )

        logger.info(
            f"Graph built: {G.number_of_nodes()} nodes, "
            f"{G.number_of_edges()} edges"
        )

        return G

    # ------------------------------------------------------------------ #
    #  Full Analysis
    # ------------------------------------------------------------------ #

    def analyze(self, graph: nx.DiGraph) -> dict[str, Any]:
        """Perform comprehensive graph analysis.

        Computes all centrality metrics, community structure, connected
        components, and topological properties.

        Args:
            graph: NetworkX directed graph from :meth:`build_graph`.

        Returns:
            Dictionary containing:
            - ``betweenness``: betweenness centrality scores
            - ``eigenvector``: eigenvector centrality scores
            - ``pagerank``: PageRank scores
            - ``in_degree``: in-degree centrality
            - ``out_degree``: out-degree centrality
            - ``communities``: list of CommunityResult
            - ``components``: connected component analysis
            - ``topology``: network density, diameter, avg path length
            - ``key_nodes``: top-N nodes per metric
        """
        if graph.number_of_nodes() == 0:
            return self._empty_result()

        # Compute centrality metrics
        betweenness = self._betweenness_centrality(graph)
        eigenvector = self._eigenvector_centrality(graph)
        pr = self._pagerank(graph)
        in_degree = self._in_degree_centrality(graph)
        out_degree = self._out_degree_centrality(graph)

        # Community detection
        communities = self._detect_communities(graph)

        # Connected components
        components = self._connected_components(graph)

        # Topological metrics
        topology = self._topology_metrics(graph)

        # Key nodes identification
        key_nodes = self._identify_key_nodes(
            betweenness, eigenvector, pr, in_degree, out_degree
        )

        result = {
            "betweenness": betweenness,
            "eigenvector": eigenvector,
            "pagerank": pr,
            "in_degree": in_degree,
            "out_degree": out_degree,
            "communities": communities,
            "components": components,
            "topology": topology,
            "key_nodes": key_nodes,
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
        }

        logger.info(
            f"Graph analysis complete: "
            f"{len(communities)} communities, "
            f"{len(components)} components"
        )

        return result

    # ------------------------------------------------------------------ #
    #  Centrality Metrics
    # ------------------------------------------------------------------ #

    def _betweenness_centrality(self, graph: nx.DiGraph) -> dict[str, float]:
        """Compute betweenness centrality for all nodes.

        Betweenness centrality of a node v is the fraction of all
        shortest paths between pairs of nodes that pass through v:

            C_B(v) = sum_{s != v != t} sigma(s,t|v) / sigma(s,t)

        where sigma(s,t) is the total number of shortest paths from s to t,
        and sigma(s,t|v) is the number that pass through v.

        High betweenness nodes are critical bridges in the network topology.

        Reference:
            Freeman, L. C. (1977). A Set of Measures of Centrality Based
            on Betweenness. Sociometry, 40(1), 35-41.
        """
        try:
            return nx.betweenness_centrality(graph, weight="weight", normalized=True)
        except Exception as exc:
            logger.warning(f"Betweenness centrality error: {exc}")
            return {node: 0.0 for node in graph.nodes()}

    def _eigenvector_centrality(self, graph: nx.DiGraph) -> dict[str, float]:
        """Compute eigenvector centrality for all nodes.

        A node's eigenvector centrality is proportional to the sum of
        the centralities of its neighbours. High eigenvector centrality
        means a node is connected to other important nodes.

        Uses the dominant eigenvector of the adjacency matrix, computed
        via power iteration.

        Reference:
            Bonacich, P. (1987). Power and Centrality: A Family of Measures.
            American Journal of Sociology, 92(5), 1170-1182.
        """
        try:
            return nx.eigenvector_centrality(
                graph, max_iter=1000, weight="weight"
            )
        except nx.NetworkXException:
            # Fall back to unweighted if convergence fails
            try:
                return nx.eigenvector_centrality(graph, max_iter=1000)
            except nx.NetworkXException:
                return {node: 0.0 for node in graph.nodes()}

    def _pagerank(self, graph: nx.DiGraph) -> dict[str, float]:
        """Compute PageRank scores for all nodes.

        PageRank models a random surfer who follows links with probability d
        (damping factor) and teleports to a random node with probability (1-d):

            PR(v) = (1-d)/N + d * sum_{u in B(v)} PR(u) / L(u)

        Reference:
            Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).
            The PageRank Citation Ranking: Bringing Order to the Web.
            Stanford InfoLab Technical Report 1999-66.
        """
        try:
            return nx.pagerank(graph, alpha=0.85, weight="weight", max_iter=200)
        except nx.NetworkXException as exc:
            logger.warning(f"PageRank computation error: {exc}")
            n = graph.number_of_nodes()
            return {node: 1.0 / n if n > 0 else 0.0 for node in graph.nodes()}

    def _in_degree_centrality(self, graph: nx.DiGraph) -> dict[str, float]:
        """Compute normalised in-degree centrality.

        In-degree centrality measures how many hosts communicate TO a node:

            C_D^in(v) = deg_in(v) / (N - 1)

        High in-degree indicates a server or service endpoint.
        """
        return nx.in_degree_centrality(graph)

    def _out_degree_centrality(self, graph: nx.DiGraph) -> dict[str, float]:
        """Compute normalised out-degree centrality.

        Out-degree centrality measures how many hosts a node communicates WITH:

            C_D^out(v) = deg_out(v) / (N - 1)

        High out-degree may indicate a scanner, spider, or compromised host.
        """
        return nx.out_degree_centrality(graph)

    # ------------------------------------------------------------------ #
    #  Community Detection
    # ------------------------------------------------------------------ #

    def _detect_communities(self, graph: nx.DiGraph) -> list[CommunityResult]:
        """Detect community structure using greedy modularity optimisation.

        Uses the Clauset-Newman-Moore algorithm, which is a greedy
        agglomerative approach that maximises the modularity function:

            Q = (1/2m) * Sum[A_ij - k_i*k_j/(2m)] * delta(c_i, c_j)

        where A_ij is the adjacency matrix, k_i is the degree of node i,
        m is the total number of edges, and delta(c_i, c_j) is 1 if nodes
        i and j are in the same community.

        This is related to the Louvain method (Blondel et al., 2008) but
        uses a different optimisation strategy.

        Reference:
            Clauset, A., Newman, M. E. J., & Moore, C. (2004). Finding
            community structure in very large networks.
            Physical Review E, 70(6), 066111.

        Reference:
            Blondel, V. D., Guillaume, J.-L., Lambiotte, R., & Lefebvre, E.
            (2008). Fast unfolding of communities in large networks.
            Journal of Statistical Mechanics, 2008(10), P10008.
        """
        communities: list[CommunityResult] = []

        # Convert to undirected for community detection
        undirected = graph.to_undirected()

        if undirected.number_of_nodes() < 2:
            if undirected.number_of_nodes() == 1:
                node = list(undirected.nodes())[0]
                communities.append(CommunityResult(
                    community_id=0,
                    members=[node],
                    internal_edges=0,
                    external_edges=0,
                    density=0.0,
                ))
            return communities

        try:
            # Use greedy modularity communities (Clauset-Newman-Moore)
            detected = nx.community.greedy_modularity_communities(
                undirected, weight="weight"
            )

            for idx, community_nodes in enumerate(detected):
                members = sorted(community_nodes)
                subgraph = undirected.subgraph(members)
                internal_edges = subgraph.number_of_edges()

                # Count external edges (edges crossing community boundary)
                external_edges = 0
                for node in members:
                    for neighbor in undirected.neighbors(node):
                        if neighbor not in community_nodes:
                            external_edges += 1

                # Compute density: 2*E / (N*(N-1)) for undirected graphs
                n = len(members)
                max_edges = n * (n - 1) / 2 if n > 1 else 1
                density = internal_edges / max_edges if max_edges > 0 else 0.0

                communities.append(CommunityResult(
                    community_id=idx,
                    members=members,
                    internal_edges=internal_edges,
                    external_edges=external_edges,
                    density=density,
                ))

        except Exception as exc:
            logger.warning(f"Community detection error: {exc}")
            # Fallback: each connected component is a community
            for idx, component in enumerate(nx.connected_components(undirected)):
                members = sorted(component)
                subgraph = undirected.subgraph(members)
                communities.append(CommunityResult(
                    community_id=idx,
                    members=members,
                    internal_edges=subgraph.number_of_edges(),
                    external_edges=0,
                    density=nx.density(subgraph) if len(members) > 1 else 0.0,
                ))

        return communities

    # ------------------------------------------------------------------ #
    #  Connected Components
    # ------------------------------------------------------------------ #

    def _connected_components(self, graph: nx.DiGraph) -> dict[str, Any]:
        """Analyse connected components of the communication graph.

        Reports both strongly connected components (all nodes mutually
        reachable) and weakly connected components (reachable ignoring
        edge direction).

        Reference:
            Tarjan, R. E. (1972). Depth-first search and linear graph
            algorithms. SIAM Journal on Computing, 1(2), 146-160.
        """
        # Weakly connected components
        weak_components = list(nx.weakly_connected_components(graph))
        weak_components.sort(key=len, reverse=True)

        # Strongly connected components
        strong_components = list(nx.strongly_connected_components(graph))
        strong_components.sort(key=len, reverse=True)

        return {
            "weakly_connected": {
                "count": len(weak_components),
                "sizes": [len(c) for c in weak_components],
                "largest": sorted(weak_components[0]) if weak_components else [],
            },
            "strongly_connected": {
                "count": len(strong_components),
                "sizes": [len(c) for c in strong_components],
                "largest": sorted(strong_components[0]) if strong_components else [],
            },
        }

    # ------------------------------------------------------------------ #
    #  Topological Metrics
    # ------------------------------------------------------------------ #

    def _topology_metrics(self, graph: nx.DiGraph) -> dict[str, Any]:
        """Compute topological properties of the network graph.

        Metrics:
        - Density: ratio of actual edges to maximum possible edges.
        - Diameter: longest shortest path in the graph (if connected).
        - Average path length: mean shortest path length.
        - Clustering coefficient: tendency of nodes to cluster together.

        Reference:
            Newman, M. E. J. (2010). Networks: An Introduction.
            Oxford University Press. Chapters 6-7.
        """
        metrics: dict[str, Any] = {
            "density": nx.density(graph),
            "diameter": None,
            "avg_path_length": None,
            "avg_clustering": None,
            "transitivity": None,
            "reciprocity": None,
        }

        # Diameter and average path length (only for connected graphs)
        try:
            if nx.is_weakly_connected(graph):
                undirected = graph.to_undirected()
                metrics["diameter"] = nx.diameter(undirected)
                metrics["avg_path_length"] = nx.average_shortest_path_length(
                    undirected
                )
            else:
                # Use largest weakly connected component
                largest_wcc = max(
                    nx.weakly_connected_components(graph), key=len
                )
                subgraph = graph.subgraph(largest_wcc).to_undirected()
                if subgraph.number_of_nodes() > 1:
                    metrics["diameter"] = nx.diameter(subgraph)
                    metrics["avg_path_length"] = (
                        nx.average_shortest_path_length(subgraph)
                    )
        except (nx.NetworkXError, ValueError):
            pass

        # Clustering coefficient (on undirected version)
        try:
            undirected = graph.to_undirected()
            metrics["avg_clustering"] = nx.average_clustering(undirected)
            metrics["transitivity"] = nx.transitivity(undirected)
        except (nx.NetworkXError, ZeroDivisionError):
            metrics["avg_clustering"] = 0.0
            metrics["transitivity"] = 0.0

        # Reciprocity (fraction of edges that are reciprocated)
        try:
            metrics["reciprocity"] = nx.overall_reciprocity(graph)
        except (nx.NetworkXError, ZeroDivisionError):
            metrics["reciprocity"] = 0.0

        return metrics

    # ------------------------------------------------------------------ #
    #  Key Node Identification
    # ------------------------------------------------------------------ #

    def _identify_key_nodes(
        self,
        betweenness: dict[str, float],
        eigenvector: dict[str, float],
        pagerank_scores: dict[str, float],
        in_degree: dict[str, float],
        out_degree: dict[str, float],
    ) -> dict[str, list[tuple[str, float]]]:
        """Identify the top-N nodes for each centrality metric.

        Returns the most important nodes according to each measure,
        providing a multi-faceted view of node importance in the network.

        Args:
            betweenness: Betweenness centrality scores.
            eigenvector: Eigenvector centrality scores.
            pagerank_scores: PageRank scores.
            in_degree: In-degree centrality scores.
            out_degree: Out-degree centrality scores.

        Returns:
            Dictionary mapping metric name to list of (node, score) tuples
            sorted by score descending.
        """
        def _top_n(scores: dict[str, float]) -> list[tuple[str, float]]:
            return sorted(
                scores.items(), key=lambda x: x[1], reverse=True
            )[:self.top_n]

        return {
            "betweenness": _top_n(betweenness),
            "eigenvector": _top_n(eigenvector),
            "pagerank": _top_n(pagerank_scores),
            "in_degree": _top_n(in_degree),
            "out_degree": _top_n(out_degree),
        }

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    def _empty_result(self) -> dict[str, Any]:
        """Return an empty analysis result."""
        return {
            "betweenness": {},
            "eigenvector": {},
            "pagerank": {},
            "in_degree": {},
            "out_degree": {},
            "communities": [],
            "components": {
                "weakly_connected": {"count": 0, "sizes": [], "largest": []},
                "strongly_connected": {"count": 0, "sizes": [], "largest": []},
            },
            "topology": {
                "density": 0.0,
                "diameter": None,
                "avg_path_length": None,
                "avg_clustering": None,
                "transitivity": None,
                "reciprocity": None,
            },
            "key_nodes": {
                "betweenness": [],
                "eigenvector": [],
                "pagerank": [],
                "in_degree": [],
                "out_degree": [],
            },
            "node_count": 0,
            "edge_count": 0,
        }
