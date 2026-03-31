"""Web server — FastAPI dashboard for interactive graph exploration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.search import HybridSearcher
from archgraph.tool.impact import ImpactAnalyzer

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


def create_app(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "archgraph",
    neo4j_database: str = "neo4j",
) -> Any:
    """Create FastAPI application."""
    if not _FASTAPI_AVAILABLE:
        raise ImportError("fastapi and uvicorn required: pip install fastapi uvicorn")

    store = Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database)
    searcher = HybridSearcher(store)
    impact = ImpactAnalyzer(store)

    app = FastAPI(title="ArchGraph Dashboard", version="0.1.0")

    @app.on_event("startup")
    def startup() -> None:
        store.connect()
        searcher.build_index()

    @app.on_event("shutdown")
    def shutdown() -> None:
        store.close()

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return _DASHBOARD_HTML

    @app.get("/api/stats")
    def get_stats() -> dict[str, Any]:
        stats = store.stats()
        return stats

    @app.get("/api/schema")
    def get_schema() -> dict[str, Any]:
        return store.schema_info()

    @app.get("/api/search")
    def search(
        q: str = Query(..., description="Search query"),
        top_k: int = Query(20, description="Number of results"),
        label: str | None = Query(None, description="Filter by node label"),
    ) -> list[dict[str, Any]]:
        return searcher.search(q, top_k=top_k, label_filter=label)

    @app.get("/api/node/{node_id:path}")
    def get_node(node_id: str) -> dict[str, Any]:
        results = store.query(
            "MATCH (n:_Node {_id: $id}) RETURN properties(n) AS props, labels(n) AS labels",
            {"id": node_id},
        )
        if not results:
            raise HTTPException(404, f"Node not found: {node_id}")
        return results[0]

    @app.get("/api/callers/{node_id:path}")
    def get_callers(node_id: str, depth: int = Query(3, ge=1, le=10)) -> list[dict[str, Any]]:
        cypher = (
            f"MATCH (f:Function)-[:CALLS*1..{depth}]->(n:_Node {{_id: $id}}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file "
            "ORDER BY f.name LIMIT 100"
        )
        return store.query(cypher, {"id": node_id})

    @app.get("/api/callees/{node_id:path}")
    def get_callees(node_id: str, depth: int = Query(3, ge=1, le=10)) -> list[dict[str, Any]]:
        cypher = (
            f"MATCH (n:_Node {{_id: $id}})-[:CALLS*1..{depth}]->(f:Function) "
            "RETURN f._id AS id, f.name AS name, f.file AS file "
            "ORDER BY f.name LIMIT 100"
        )
        return store.query(cypher, {"id": node_id})

    @app.get("/api/security")
    def get_security() -> dict[str, Any]:
        inputs = store.query(
            "MATCH (f:Function {is_input_source: true}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file LIMIT 50"
        )
        sinks = store.query(
            "MATCH (f:Function {is_dangerous_sink: true}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file LIMIT 50"
        )
        taint = store.query(
            "MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->"
            "(sink:Function {is_dangerous_sink: true}) "
            "RETURN src.name AS source, sink.name AS sink, length(path) AS depth "
            "ORDER BY depth LIMIT 30"
        )
        vulns = store.query(
            "MATCH (v:Vulnerability) "
            "RETURN v.vuln_id AS id, v.summary AS summary, v.severity AS severity LIMIT 50"
        )
        return {
            "input_sources": inputs,
            "dangerous_sinks": sinks,
            "taint_paths": taint,
            "vulnerabilities": vulns,
        }

    @app.get("/api/clusters")
    def get_clusters() -> list[dict[str, Any]]:
        return store.query(
            "MATCH (c:Cluster) "
            "RETURN c._id AS id, c.name AS name, c.size AS size, c.cohesion AS cohesion "
            "ORDER BY c.size DESC"
        )

    @app.get("/api/processes")
    def get_processes() -> list[dict[str, Any]]:
        return store.query(
            "MATCH (p:Process) "
            "RETURN p._id AS id, p.name AS name, p.type AS type, p.step_count AS steps "
            "ORDER BY p.step_count DESC"
        )

    @app.get("/api/graph/neighbors/{node_id:path}")
    def get_neighbors(node_id: str) -> dict[str, Any]:
        """Get immediate neighbors for graph visualization."""
        nodes = store.query(
            "MATCH (n:_Node {_id: $id})-[r]-(m:_Node) "
            "RETURN m._id AS id, labels(m) AS labels, properties(m) AS props, type(r) AS rel_type "
            "LIMIT 50",
            {"id": node_id},
        )
        return {"center": node_id, "neighbors": nodes}

    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    **kwargs: Any,
) -> None:
    """Run the web dashboard server."""
    if not _FASTAPI_AVAILABLE:
        raise ImportError("fastapi and uvicorn required: pip install fastapi uvicorn")

    app = create_app(**kwargs)
    logger.info("Starting ArchGraph dashboard at http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port)


# ── Embedded Dashboard HTML ─────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArchGraph Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
        .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
        .header h1 { font-size: 20px; color: #58a6ff; }
        .header .badge { background: #238636; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
        .container { display: grid; grid-template-columns: 280px 1fr 320px; height: calc(100vh - 57px); }
        .sidebar { background: #161b22; border-right: 1px solid #30363d; overflow-y: auto; padding: 16px; }
        .main { padding: 16px; overflow-y: auto; }
        .detail { background: #161b22; border-left: 1px solid #30363d; overflow-y: auto; padding: 16px; }
        .search-box { width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; margin-bottom: 16px; }
        .search-box:focus { outline: none; border-color: #58a6ff; }
        .stat-card { background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
        .stat-card h3 { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-bottom: 4px; }
        .stat-card .value { font-size: 28px; font-weight: 600; color: #58a6ff; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
        .result-item { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: border-color 0.2s; }
        .result-item:hover { border-color: #58a6ff; }
        .result-item .name { font-weight: 600; color: #c9d1d9; }
        .result-item .file { font-size: 12px; color: #8b949e; margin-top: 2px; }
        .result-item .score { float: right; background: #30363d; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .result-item .snippet { font-size: 12px; color: #8b949e; margin-top: 6px; font-family: monospace; }
        .security-badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; margin-left: 6px; }
        .badge-input { background: #da3633; color: white; }
        .badge-sink { background: #f0883e; color: white; }
        .tabs { display: flex; gap: 4px; margin-bottom: 16px; }
        .tab { padding: 8px 16px; background: #21262d; border: 1px solid #30363d; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .tab.active { background: #388bfd26; border-color: #58a6ff; color: #58a6ff; }
        .detail h2 { font-size: 16px; margin-bottom: 12px; color: #58a6ff; }
        .detail-section { margin-bottom: 16px; }
        .detail-section h4 { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
        .detail-list { list-style: none; }
        .detail-list li { padding: 6px 0; border-bottom: 1px solid #21262d; font-size: 13px; }
        .detail-list li:hover { color: #58a6ff; cursor: pointer; }
        .empty-state { text-align: center; padding: 40px; color: #8b949e; }
        .loading { text-align: center; padding: 20px; color: #8b949e; }
        .section-title { font-size: 14px; font-weight: 600; color: #8b949e; text-transform: uppercase; margin-bottom: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 ArchGraph</h1>
        <span class="badge">Dashboard</span>
        <span id="status" style="margin-left:auto;font-size:13px;color:#8b949e">Loading...</span>
    </div>
    <div class="container">
        <div class="sidebar">
            <input type="text" class="search-box" id="searchInput" placeholder="Search functions, classes, files...">
            <div class="tabs">
                <div class="tab active" data-tab="stats">Stats</div>
                <div class="tab" data-tab="security">Security</div>
                <div class="tab" data-tab="clusters">Clusters</div>
            </div>
            <div id="sidebarContent"></div>
        </div>
        <div class="main">
            <div id="searchResults"></div>
            <div id="mainContent"></div>
        </div>
        <div class="detail" id="detailPanel">
            <div class="empty-state">Select a node to see details</div>
        </div>
    </div>
    <script>
        const API = '';
        let currentTab = 'stats';
        let searchTimeout;

        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                currentTab = tab.dataset.tab;
                loadSidebar();
            });
        });

        // Search
        document.getElementById('searchInput').addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => performSearch(e.target.value), 300);
        });

        async function performSearch(query) {
            const resultsEl = document.getElementById('searchResults');
            const mainEl = document.getElementById('mainContent');
            if (!query) {
                resultsEl.innerHTML = '';
                mainEl.style.display = 'block';
                return;
            }
            mainEl.style.display = 'none';
            resultsEl.innerHTML = '<div class="loading">Searching...</div>';
            try {
                const res = await fetch(API + '/api/search?q=' + encodeURIComponent(query));
                const results = await res.json();
                if (results.length === 0) {
                    resultsEl.innerHTML = '<div class="empty-state">No results found</div>';
                    return;
                }
                resultsEl.innerHTML = results.map(r => `
                    <div class="result-item" onclick="showNode('${r.id}')">
                        <span class="score">${(r.score * 100).toFixed(0)}%</span>
                        <div class="name">
                            ${r.name || r.id}
                            ${r.security.is_input_source ? '<span class="security-badge badge-input">INPUT</span>' : ''}
                            ${r.security.is_dangerous_sink ? '<span class="security-badge badge-sink">SINK</span>' : ''}
                        </div>
                        <div class="file">${r.file || ''}</div>
                        ${r.snippet ? '<div class="snippet">' + r.snippet + '</div>' : ''}
                    </div>
                `).join('');
            } catch (e) {
                resultsEl.innerHTML = '<div class="empty-state">Search failed</div>';
            }
        }

        async function loadSidebar() {
            const el = document.getElementById('sidebarContent');
            if (currentTab === 'stats') {
                const res = await fetch(API + '/api/stats');
                const stats = await res.json();
                const nodes = stats.nodes || {};
                const edges = stats.edges || {};
                let html = '<div class="section-title">Nodes</div>';
                for (const [label, count] of Object.entries(nodes)) {
                    if (label === '_Node') continue;
                    html += `<div class="stat-card"><h3>${label}</h3><div class="value">${count}</div></div>`;
                }
                html += '<div class="section-title">Edges</div>';
                for (const [type, count] of Object.entries(edges)) {
                    html += `<div class="stat-card"><h3>${type}</h3><div class="value">${count}</div></div>`;
                }
                el.innerHTML = html;
            } else if (currentTab === 'security') {
                const res = await fetch(API + '/api/security');
                const sec = await res.json();
                let html = `<div class="section-title">Input Sources (${sec.input_sources.length})</div>`;
                sec.input_sources.slice(0, 10).forEach(s => {
                    html += `<div class="result-item" onclick="showNode('${s.id}')"><div class="name">${s.name}</div><div class="file">${s.file}</div></div>`;
                });
                html += `<div class="section-title">Dangerous Sinks (${sec.dangerous_sinks.length})</div>`;
                sec.dangerous_sinks.slice(0, 10).forEach(s => {
                    html += `<div class="result-item" onclick="showNode('${s.id}')"><div class="name">${s.name}</div><div class="file">${s.file}</div></div>`;
                });
                html += `<div class="section-title">Taint Paths (${sec.taint_paths.length})</div>`;
                sec.taint_paths.slice(0, 10).forEach(t => {
                    html += `<div class="result-item"><div class="name">${t.source} → ${t.sink}</div><div class="file">depth: ${t.depth}</div></div>`;
                });
                el.innerHTML = html;
            } else if (currentTab === 'clusters') {
                const res = await fetch(API + '/api/clusters');
                const clusters = await res.json();
                let html = `<div class="section-title">Clusters (${clusters.length})</div>`;
                clusters.forEach(c => {
                    html += `<div class="result-item"><div class="name">${c.name}</div><div class="file">${c.size} functions | cohesion: ${c.cohesion}</div></div>`;
                });
                el.innerHTML = html;
            }
        }

        async function showNode(nodeId) {
            const panel = document.getElementById('detailPanel');
            panel.innerHTML = '<div class="loading">Loading...</div>';
            try {
                const [nodeRes, callersRes, calleesRes] = await Promise.all([
                    fetch(API + '/api/node/' + encodeURIComponent(nodeId)),
                    fetch(API + '/api/callers/' + encodeURIComponent(nodeId)),
                    fetch(API + '/api/callees/' + encodeURIComponent(nodeId)),
                ]);
                const node = await nodeRes.json();
                const callers = await callersRes.json();
                const callees = await calleesRes.json();
                const props = node.props || {};
                const labels = (node.labels || []).filter(l => l !== '_Node');
                let html = `<h2>${props.name || nodeId}</h2>`;
                html += `<div class="detail-section"><h4>Labels</h4><p>${labels.join(', ')}</p></div>`;
                html += `<div class="detail-section"><h4>Properties</h4><ul class="detail-list">`;
                for (const [k, v] of Object.entries(props)) {
                    if (k === '_id' || !v) continue;
                    html += `<li><strong>${k}:</strong> ${typeof v === 'object' ? JSON.stringify(v) : v}</li>`;
                }
                html += `</ul></div>`;
                if (callers.length) {
                    html += `<div class="detail-section"><h4>Callers (${callers.length})</h4><ul class="detail-list">`;
                    callers.slice(0, 20).forEach(c => {
                        html += `<li onclick="showNode('${c.id}')">${c.name} <span style="color:#8b949e">${c.file}</span></li>`;
                    });
                    html += `</ul></div>`;
                }
                if (callees.length) {
                    html += `<div class="detail-section"><h4>Callees (${callees.length})</h4><ul class="detail-list">`;
                    callees.slice(0, 20).forEach(c => {
                        html += `<li onclick="showNode('${c.id}')">${c.name} <span style="color:#8b949e">${c.file}</span></li>`;
                    });
                    html += `</ul></div>`;
                }
                panel.innerHTML = html;
            } catch (e) {
                panel.innerHTML = '<div class="empty-state">Failed to load node details</div>';
            }
        }

        // Initial load
        async function init() {
            try {
                await loadSidebar();
                document.getElementById('status').textContent = 'Connected';
                document.getElementById('status').style.color = '#3fb950';
                const mainEl = document.getElementById('mainContent');
                const res = await fetch(API + '/api/stats');
                const stats = await res.json();
                const nodes = stats.nodes || {};
                const edges = stats.edges || {};
                let html = '<div class="section-title" style="font-size:18px;margin-bottom:20px">Codebase Overview</div>';
                html += '<div class="stat-grid">';
                const totalNodes = Object.entries(nodes).filter(([k]) => k !== '_Node').reduce((s, [, v]) => s + v, 0);
                const totalEdges = Object.values(edges).reduce((s, v) => s + v, 0);
                html += `<div class="stat-card"><h3>Total Nodes</h3><div class="value">${totalNodes}</div></div>`;
                html += `<div class="stat-card"><h3>Total Edges</h3><div class="value">${totalEdges}</div></div>`;
                html += `</div>`;
                html += '<div style="color:#8b949e;text-align:center;padding:20px">Use the search bar to explore the graph</div>';
                mainEl.innerHTML = html;
            } catch (e) {
                document.getElementById('status').textContent = 'Disconnected';
                document.getElementById('status').style.color = '#f85149';
            }
        }
        init();
    </script>
</body>
</html>"""
