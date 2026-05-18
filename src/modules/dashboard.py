"""
HTML dashboard generator — produces a single self-contained report file.
"""

import base64
import html as html_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class DashboardGenerator:
    """Renders recon results into a standalone HTML dashboard."""

    def __init__(self, output_path: str = "report.html"):
        self.output_path = Path(output_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate(self, data: Dict[str, Any]) -> str:
        """Build the HTML report and write it to *output_path*. Returns the path."""
        target = data.get("target", "unknown")
        subdomains = data.get("subdomains", [])
        summary = data.get("summary", {})
        correlated = data.get("correlated_findings", [])
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        cards_html = self._render_summary_cards(summary, data.get("total_unique", 0))
        findings_html = self._render_findings(correlated)
        recommendations_html = self._render_recommendations([])
        table_html = self._render_table(subdomains)

        page = self._page_template(
            target=target,
            timestamp=timestamp,
            cards=cards_html,
            findings=findings_html,
            recommendations=recommendations_html,
            table=table_html,
        )

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(page, encoding="utf-8")
        return str(self.output_path)

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------
    def _render_summary_cards(self, summary: Dict[str, int], total: int) -> str:
        cards = [
            ("Discovered", total, "#6c7ae0"),
            ("Responsive", summary.get("alive", 0), "#2ecc71"),
            ("Unresponsive", summary.get("dead", 0), "#95a5a6"),
            ("Error", summary.get("error", 0), "#e74c3c"),
        ]
        parts: List[str] = []
        for label, count, color in cards:
            parts.append(
                f'<div class="card" style="border-top:4px solid {color}">'
                f'<span class="card-count">{count}</span>'
                f'<span class="card-label">{label}</span></div>'
            )
        return "\n".join(parts)

    @staticmethod
    def _render_findings(findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return '<p class="muted">No correlated findings.</p>'
        sev_colors = {
            "critical": "#c0392b", "high": "#e74c3c",
            "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6",
        }
        parts: List[str] = []
        for f in findings:
            sev = f.get("severity", "info")
            color = sev_colors.get(sev, "#95a5a6")
            title = html_mod.escape(f.get("title", ""))
            desc = html_mod.escape(f.get("description", ""))
            evidence = f.get("evidence", [])
            ev_html = "".join(f"<li>{html_mod.escape(e)}</li>" for e in evidence)
            parts.append(
                f'<details class="finding" style="border-left:4px solid {color}">'
                f'<summary><span class="badge" style="background:{color}33;color:{color}">'
                f"{sev.upper()}</span> {title}</summary>"
                f"<p>{desc}</p>"
                f'<ul class="evidence">{ev_html}</ul></details>'
            )
        return "\n".join(parts)

    @staticmethod
    def _render_recommendations(recs: List[str]) -> str:
        if not recs:
            return '<p class="muted">No recommendations.</p>'
        items = "".join(f"<li>{html_mod.escape(r)}</li>" for r in recs)
        return f'<ol class="recs">{items}</ol>'

    def _render_table(self, subdomains: List[Dict[str, Any]]) -> str:
        rows: List[str] = []
        for entry in subdomains:
            badge = self._status_badge(entry)
            title = html_mod.escape(entry.get("title") or "—")
            redirect = html_mod.escape(entry.get("redirect_url") or "—")
            resp_time = entry.get("response_time")
            resp_time_str = f"{resp_time}s" if resp_time is not None else "—"
            content_len = entry.get("content_length")
            content_len_str = self._human_bytes(content_len) if content_len is not None else "—"
            screenshot = self._screenshot_thumbnail(entry.get("screenshot_path"))
            tags_html = self._render_tags(entry.get("tags", []))
            risk = self._risk_badge(entry.get("content_analysis", {}))
            headers_grade = self._header_grade_badge(entry.get("header_analysis"))

            rows.append(
                "<tr>"
                f'<td class="mono">{html_mod.escape(entry["subdomain"])}</td>'
                f"<td>{badge}</td>"
                f"<td>{title}</td>"
                f"<td>{tags_html}</td>"
                f"<td>{risk}</td>"
                f"<td>{headers_grade}</td>"
                f"<td>{redirect}</td>"
                f"<td>{resp_time_str}</td>"
                f"<td>{content_len_str}</td>"
                f"<td>{screenshot}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    # ------------------------------------------------------------------
    # Tiny utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _status_badge(entry: Dict[str, Any]) -> str:
        code = entry.get("status_code")
        if not entry.get("alive") or code is None:
            return '<span class="badge dead">DOWN</span>'
        color_cls = "alive" if 200 <= code < 400 else ("error" if code >= 500 else "warn")
        return f'<span class="badge {color_cls}">{code}</span>'

    @staticmethod
    def _render_tags(tags: List[str]) -> str:
        if not tags:
            return "—"
        tag_colors = {
            "login": "#3498db", "admin-panel": "#e74c3c", "api-docs": "#9b59b6",
            "default-install": "#e67e22", "error-page": "#95a5a6", "webmail": "#1abc9c",
            "dev-staging": "#e74c3c", "cms": "#2ecc71", "cdn-static": "#6c7ae0",
            "monitoring": "#f39c12", "ci-cd": "#c0392b", "database": "#c0392b",
            "vpn-internal": "#e67e22", "parking-page": "#7f8c8d", "blank-page": "#7f8c8d",
            "forbidden": "#f39c12",
        }
        pills = []
        for tag in tags:
            color = tag_colors.get(tag, "#6c7ae0")
            pills.append(
                f'<span class="tag" style="background:{color}22;color:{color};'
                f'border:1px solid {color}44">{html_mod.escape(tag)}</span>'
            )
        return " ".join(pills)

    @staticmethod
    def _risk_badge(analysis: Dict[str, Any]) -> str:
        level = analysis.get("risk_level", "info")
        colors = {
            "critical": "#c0392b", "high": "#e74c3c",
            "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6",
        }
        color = colors.get(level, "#95a5a6")
        return f'<span class="badge" style="background:{color}33;color:{color}">{level.upper()}</span>'

    @staticmethod
    def _header_grade_badge(analysis: Optional[Dict[str, Any]]) -> str:
        if not analysis:
            return "—"
        grade = analysis.get("grade", "—")
        score = analysis.get("score", 0)
        color_map = {"A": "#2ecc71", "B": "#3498db", "C": "#f39c12", "D": "#e67e22", "F": "#e74c3c"}
        color = color_map.get(grade, "#95a5a6")
        return f'<span class="badge" style="background:{color}33;color:{color}">{grade} ({score})</span>'

    @staticmethod
    def _screenshot_thumbnail(path: Optional[str]) -> str:
        if not path:
            return "—"
        p = Path(path)
        if not p.exists():
            return "—"
        try:
            data = base64.b64encode(p.read_bytes()).decode()
            return (
                f'<img class="thumb" src="data:image/png;base64,{data}" '
                f'onclick="this.classList.toggle(\'expanded\')" />'
            )
        except Exception:
            return "—"

    @staticmethod
    def _human_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB"):
            if n < 1024:
                return f"{n:.0f}{unit}"
            n /= 1024
        return f"{n:.1f}GB"

    # ------------------------------------------------------------------
    # Full page template
    # ------------------------------------------------------------------
    @staticmethod
    def _page_template(
        target: str,
        timestamp: str,
        cards: str,
        findings: str,
        recommendations: str,
        table: str,
    ) -> str:
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Recon — {html_mod.escape(target)}</title>
<style>
:root{{--bg:#1a1a2e;--surface:#16213e;--border:#0f3460;--text:#e0e0e0;--muted:#888}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}}
h1{{font-size:1.6rem;margin-bottom:.3rem}}
h2{{font-size:1.2rem;margin:2rem 0 .8rem;color:#ccc}}
.meta{{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}}
.muted{{color:var(--muted)}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.card{{background:var(--surface);border-radius:8px;padding:1.2rem 1.6rem;min-width:140px;display:flex;flex-direction:column;align-items:center}}
.card-count{{font-size:2rem;font-weight:700}}
.card-label{{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.2rem}}
.finding{{background:var(--surface);border-radius:6px;padding:.8rem 1rem;margin-bottom:.5rem;cursor:pointer}}
.finding summary{{font-weight:600;font-size:.88rem;display:flex;align-items:center;gap:.5rem}}
.finding p{{margin:.5rem 0;font-size:.82rem;color:var(--muted)}}
.evidence{{font-size:.78rem;color:var(--muted);margin:.3rem 0 0 1.2rem}}
.recs{{margin:.5rem 0 0 1.2rem;font-size:.85rem}}
.recs li{{margin-bottom:.4rem}}
#filter{{margin-bottom:1rem;padding:.5rem .8rem;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);width:320px;font-size:.9rem}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:.6rem .8rem;background:var(--surface);border-bottom:2px solid var(--border);position:sticky;top:0;cursor:pointer;user-select:none}}
td{{padding:.5rem .8rem;border-bottom:1px solid var(--border)}}
tr:hover{{background:rgba(255,255,255,.04)}}
.mono{{font-family:'Cascadia Code',Consolas,monospace}}
.badge{{padding:2px 8px;border-radius:4px;font-size:.78rem;font-weight:600}}
.badge.alive{{background:#2ecc7133;color:#2ecc71}}
.badge.warn{{background:#f39c1233;color:#f39c12}}
.badge.error{{background:#e74c3c33;color:#e74c3c}}
.badge.dead{{background:#95a5a633;color:#95a5a6}}
.tag{{padding:2px 7px;border-radius:3px;font-size:.72rem;font-weight:500;margin:1px 2px;display:inline-block}}
.thumb{{height:48px;border-radius:4px;cursor:pointer;transition:all .25s ease}}
.thumb.expanded{{height:300px;position:relative;z-index:10;box-shadow:0 4px 24px rgba(0,0,0,.6)}}
</style>
</head>
<body>
<h1>[RECON] Report — {html_mod.escape(target)}</h1>
<p class="meta">Generated {html_mod.escape(timestamp)}</p>

<div class="cards">{cards}</div>

<h2>&#x26a0;&#xfe0f; Correlated Findings</h2>
{findings}

<h2>&#x1f4cb; Recommendations</h2>
{recommendations}

<h2>&#x1f310; Subdomain Details</h2>
<input id="filter" type="text" placeholder="Filter subdomains…" oninput="filterTable(this.value)"/>
<table id="results">
<thead><tr>
<th onclick="sortTable(0)">Subdomain</th>
<th onclick="sortTable(1)">Status</th>
<th onclick="sortTable(2)">Title</th>
<th onclick="sortTable(3)">Tags</th>
<th onclick="sortTable(4)">Risk</th>
<th onclick="sortTable(5)">Headers</th>
<th onclick="sortTable(6)">Redirect</th>
<th onclick="sortTable(7)">Response</th>
<th onclick="sortTable(8)">Size</th>
<th>Screenshot</th>
</tr></thead>
<tbody>{table}</tbody>
</table>
<script>
function filterTable(q){{
  q=q.toLowerCase();
  document.querySelectorAll('#results tbody tr').forEach(r=>{{
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
  }});
}}
let sortDir={{}};
function sortTable(col){{
  const tb=document.querySelector('#results tbody');
  const rows=[...tb.rows];
  sortDir[col]=!sortDir[col];
  rows.sort((a,b)=>{{
    let x=a.cells[col].textContent.trim(),y=b.cells[col].textContent.trim();
    let cmp=x.localeCompare(y,undefined,{{numeric:true}});
    return sortDir[col]?cmp:-cmp;
  }});
  rows.forEach(r=>tb.appendChild(r));
}}
</script>
</body>
</html>"""
