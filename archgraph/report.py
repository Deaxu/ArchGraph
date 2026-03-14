"""HTML report generation — single-file security report."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.graph.schema import NodeLabel

logger = logging.getLogger(__name__)


def generate_report(store: Neo4jStore, repo_path: Path, output_path: Path | None = None) -> Path:
    """Generate a single-file HTML security report.

    Args:
        store: Connected Neo4jStore
        repo_path: Repository path (for display)
        output_path: Output HTML file path (default: archgraph_report.html)

    Returns:
        Path to generated HTML file
    """
    if output_path is None:
        output_path = repo_path / "archgraph_report.html"

    # Gather data
    stats = store.stats()

    input_sources = store.query(
        "MATCH (f:Function {is_input_source: true}) "
        "RETURN f.name AS name, f.file AS file, f.risk_score AS risk "
        "ORDER BY f.risk_score DESC LIMIT 50"
    )

    dangerous_sinks = store.query(
        "MATCH (f:Function {is_dangerous_sink: true}) "
        "RETURN f.name AS name, f.file AS file, f.risk_score AS risk "
        "ORDER BY f.risk_score DESC LIMIT 50"
    )

    taint_paths = store.query(
        "MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) "
        "RETURN src.name AS source, src.file AS source_file, "
        "sink.name AS sink, sink.file AS sink_file, length(path) AS depth "
        "ORDER BY depth LIMIT 30"
    )

    high_risk = store.query(
        "MATCH (f:Function) WHERE f.risk_score > 50 "
        "RETURN f.name AS name, f.file AS file, f.risk_score AS risk "
        "ORDER BY f.risk_score DESC LIMIT 20"
    )

    vulns = store.query(
        "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) "
        "RETURN d.name AS dep, d.version AS version, "
        "v.vuln_id AS vuln_id, v.summary AS summary, v.severity AS severity "
        "ORDER BY v.severity DESC LIMIT 30"
    )

    clusters = store.query(
        "MATCH (c:Cluster) RETURN c.name AS name, c.size AS size, c.cohesion AS cohesion "
        "ORDER BY c.size DESC LIMIT 20"
    )

    processes = store.query(
        "MATCH (p:Process) RETURN p.name AS name, p.type AS type, p.step_count AS steps "
        "ORDER BY p.step_count DESC LIMIT 20"
    )

    # Generate HTML
    html = _render_html(
        repo_path=str(repo_path),
        generated_at=datetime.now().isoformat(),
        stats=stats,
        input_sources=input_sources,
        dangerous_sinks=dangerous_sinks,
        taint_paths=taint_paths,
        high_risk=high_risk,
        vulns=vulns,
        clusters=clusters,
        processes=processes,
    )

    output_path.write_text(html, encoding="utf-8")
    logger.info("Generated HTML report: %s", output_path)
    return output_path


def _render_html(**data: object) -> str:
    """Render the HTML report template."""
    stats = data.get("stats", {}) or {}
    node_counts = stats.get("nodes", {}) if isinstance(stats, dict) else {}
    edge_counts = stats.get("edges", {}) if isinstance(stats, dict) else {}

    input_sources = data.get("input_sources", []) or []
    dangerous_sinks = data.get("dangerous_sinks", []) or []
    taint_paths = data.get("taint_paths", []) or []
    high_risk = data.get("high_risk", []) or []
    vulns = data.get("vulns", []) or []
    clusters = data.get("clusters", []) or []
    processes = data.get("processes", []) or []

    def _table_rows(rows: list[dict], cols: list[str]) -> str:
        if not rows:
            return '<tr><td colspan="{}" class="empty">No data</td></tr>'.format(len(cols))
        return "\n".join(
            "<tr>" + "".join(f"<td>{row.get(c, '')}</td>" for c in cols) + "</tr>"
            for row in rows
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ArchGraph Report — {data.get('repo_path', '')}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8f9fa; color: #212529; padding: 20px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 24px; margin-bottom: 8px; color: #0d6efd; }}
  h2 {{ font-size: 18px; margin: 24px 0 12px; color: #495057; border-bottom: 2px solid #dee2e6; padding-bottom: 8px; }}
  .meta {{ color: #6c757d; margin-bottom: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .card {{ background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 16px; }}
  .card h3 {{ font-size: 12px; color: #6c757d; text-transform: uppercase; margin-bottom: 4px; }}
  .card .value {{ font-size: 28px; font-weight: 600; color: #0d6efd; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; margin-bottom: 24px; }}
  th {{ background: #f8f9fa; text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase; color: #6c757d; border-bottom: 2px solid #dee2e6; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f1f3f5; font-size: 14px; }}
  tr:hover {{ background: #f8f9fa; }}
  .empty {{ text-align: center; color: #adb5bd; padding: 20px; }}
  .risk-high {{ color: #dc3545; font-weight: 600; }}
  .risk-medium {{ color: #fd7e14; font-weight: 600; }}
  .risk-low {{ color: #198754; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }}
  .badge-critical {{ background: #dc3545; color: white; }}
  .badge-high {{ background: #fd7e14; color: white; }}
  .badge-medium {{ background: #ffc107; color: #212529; }}
  .badge-low {{ background: #198754; color: white; }}
  .severity-CRITICAL {{ color: #dc3545; font-weight: 700; }}
  .severity-HIGH {{ color: #fd7e14; font-weight: 600; }}
  .severity-MEDIUM {{ color: #ffc107; }}
  .severity-LOW {{ color: #6c757d; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 ArchGraph Security Report</h1>
  <p class="meta">Repository: <strong>{data.get('repo_path', '')}</strong> | Generated: {data.get('generated_at', '')}</p>

  <h2>📊 Graph Statistics</h2>
  <div class="grid">
    {"".join(f'<div class="card"><h3>{label}</h3><div class="value">{count}</div></div>' for label, count in sorted(node_counts.items(), key=lambda x: -x[1]) if label != '_Node') if node_counts else '<p>No data</p>'}
  </div>

  <h2>🔴 High Risk Functions (score &gt; 50)</h2>
  <table>
    <tr><th>Function</th><th>File</th><th>Risk Score</th></tr>
    {_table_rows(high_risk, ['name', 'file', 'risk'])}
  </table>

  <h2>📥 Input Sources</h2>
  <table>
    <tr><th>Function</th><th>File</th><th>Risk</th></tr>
    {_table_rows(input_sources, ['name', 'file', 'risk'])}
  </table>

  <h2>⚠️ Dangerous Sinks</h2>
  <table>
    <tr><th>Function</th><th>File</th><th>Risk</th></tr>
    {_table_rows(dangerous_sinks, ['name', 'file', 'risk'])}
  </table>

  <h2>🔗 Taint Paths (Input → Sink)</h2>
  <table>
    <tr><th>Source</th><th>Source File</th><th>Sink</th><th>Sink File</th><th>Depth</th></tr>
    {_table_rows(taint_paths, ['source', 'source_file', 'sink', 'sink_file', 'depth'])}
  </table>

  <h2>🛡️ Vulnerabilities</h2>
  <table>
    <tr><th>Dependency</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Summary</th></tr>
    {_table_rows([{**v, 'severity': f'<span class="severity-{v.get("severity", "")}">{v.get("severity", "")}</span>'} for v in vulns], ['dep', 'version', 'vuln_id', 'severity', 'summary'])}
  </table>

  <h2>🧩 Clusters</h2>
  <table>
    <tr><th>Name</th><th>Size</th><th>Cohesion</th></tr>
    {_table_rows(clusters, ['name', 'size', 'cohesion'])}
  </table>

  <h2>🔄 Processes</h2>
  <table>
    <tr><th>Name</th><th>Type</th><th>Steps</th></tr>
    {_table_rows(processes, ['name', 'type', 'steps'])}
  </table>

  <p class="meta" style="margin-top:40px;text-align:center">Generated by <strong>ArchGraph</strong> — <a href="https://github.com/archgraph/archgraph">GitHub</a></p>
</div>
</body>
</html>"""
