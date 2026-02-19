"""
Morph Report Generator
=======================

Generates HTML and JSON reports from Morph binary analysis results.
The HTML report uses inline CSS for self-contained, portable output
that can be viewed in any web browser.

The JSON report follows a structured format suitable for machine
consumption, integration with SIEMs, and downstream analysis pipelines.

References:
    - STIX/TAXII structured threat information expression formats.
    - OASIS. (2023). STIX 2.1 Specification.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from morph.core.models import (
    BinaryAnalysisResult,
    BinaryInfo,
    CFGResult,
    ImportInfo,
    SectionInfo,
    ShellcodeIndicator,
    StringCategory,
    StringResult,
)


# ---------------------------------------------------------------------------
# HTML Template Components
# ---------------------------------------------------------------------------

_HTML_HEADER = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomCore Morph - Binary Analysis Report</title>
<style>
  :root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #c9d1d9;
    --text-secondary: #8b949e;
    --accent-cyan: #58a6ff;
    --accent-magenta: #bc8cff;
    --accent-green: #3fb950;
    --accent-yellow: #d29922;
    --accent-red: #f85149;
    --accent-orange: #db6d28;
    --border-color: #30363d;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  h1, h2, h3 { color: var(--accent-cyan); margin-bottom: 1rem; }
  h1 { font-size: 2rem; border-bottom: 2px solid var(--accent-magenta); padding-bottom: 0.5rem; }
  h2 { font-size: 1.5rem; margin-top: 2rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.3rem; }
  h3 { font-size: 1.2rem; color: var(--accent-magenta); }
  .header-panel {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1.5rem;
    margin: 1rem 0;
  }
  .meta-row { display: flex; margin: 0.3rem 0; }
  .meta-label { font-weight: bold; min-width: 180px; color: var(--accent-cyan); }
  .meta-value { color: var(--text-primary); }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 1rem 0;
    background: var(--bg-secondary);
  }
  th {
    background: var(--bg-tertiary);
    color: var(--accent-magenta);
    padding: 0.6rem 0.8rem;
    text-align: left;
    border: 1px solid var(--border-color);
    font-size: 0.9rem;
  }
  td {
    padding: 0.5rem 0.8rem;
    border: 1px solid var(--border-color);
    font-size: 0.85rem;
  }
  tr:hover { background: var(--bg-tertiary); }
  .entropy-bar {
    display: inline-block;
    height: 12px;
    border-radius: 2px;
    vertical-align: middle;
  }
  .entropy-bar-bg {
    display: inline-block;
    width: 100px;
    height: 12px;
    background: var(--bg-tertiary);
    border-radius: 2px;
    vertical-align: middle;
  }
  .risk-score {
    font-size: 2rem;
    font-weight: bold;
    padding: 1rem;
    text-align: center;
    border-radius: 6px;
    margin: 1rem 0;
  }
  .risk-critical { color: var(--accent-red); border: 2px solid var(--accent-red); }
  .risk-high { color: var(--accent-orange); border: 2px solid var(--accent-orange); }
  .risk-medium { color: var(--accent-yellow); border: 2px solid var(--accent-yellow); }
  .risk-low { color: var(--accent-green); border: 2px solid var(--accent-green); }
  .tag {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: bold;
    margin: 0 0.2rem;
  }
  .tag-critical { background: var(--accent-red); color: white; }
  .tag-high { background: var(--accent-orange); color: white; }
  .tag-medium { background: var(--accent-yellow); color: black; }
  .tag-low { background: var(--accent-green); color: black; }
  .tag-info { background: var(--accent-cyan); color: black; }
  .mono { font-family: 'Consolas', 'Monaco', monospace; font-size: 0.85rem; }
  .shellcode-desc { font-size: 0.85rem; color: var(--text-secondary); }
  .footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.85rem;
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
  }
  .summary-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
  }
  .summary-card .number {
    font-size: 2rem;
    font-weight: bold;
    color: var(--accent-cyan);
  }
  .summary-card .label { color: var(--text-secondary); font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
"""

_HTML_FOOTER = """\
<div class="footer">
  <p>Generated by PhantomCore Morph - Binary Analysis Framework</p>
  <p>Report generated: {timestamp}</p>
  <p>PhantomCore &copy; 2024-2026 - Cybersecurity Educational Toolkit</p>
</div>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# MorphReportGenerator
# ---------------------------------------------------------------------------

class MorphReportGenerator:
    """Generate HTML and JSON reports from binary analysis results.

    The HTML report is a self-contained file with inline CSS that can
    be opened in any modern web browser.  The JSON report follows a
    structured format for machine consumption.

    Usage::

        generator = MorphReportGenerator()
        generator.generate_html(result, "report.html")
        generator.generate_json(result, "report.json")
    """

    def generate_html(
        self,
        result: BinaryAnalysisResult,
        output_path: str,
    ) -> str:
        """Generate a self-contained HTML analysis report.

        Args:
            result: The BinaryAnalysisResult to report.
            output_path: Filesystem path for the output HTML file.

        Returns:
            The absolute path of the generated report.
        """
        parts: list[str] = [_HTML_HEADER]

        # Title
        parts.append("<h1>PhantomCore Morph - Binary Analysis Report</h1>")

        # Binary info panel
        parts.append(self._html_binary_info(result.info))

        # Risk score
        parts.append(self._html_risk_score(result.risk_score, result.packer_detected))

        # Summary cards
        parts.append(self._html_summary_cards(result))

        # Sections
        if result.sections:
            parts.append(self._html_sections(result.sections))

        # Imports
        if result.imports:
            parts.append(self._html_imports(result.imports))

        # Strings
        if result.strings:
            parts.append(self._html_strings(result.strings))

        # Shellcode
        if result.shellcode_indicators:
            parts.append(self._html_shellcode(result.shellcode_indicators))

        # CFG
        if result.cfg and result.cfg.blocks:
            parts.append(self._html_cfg(result.cfg))

        # Footer
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(_HTML_FOOTER.format(timestamp=timestamp))

        html_content = "\n".join(parts)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")

        return str(path.resolve())

    def generate_json(
        self,
        result: BinaryAnalysisResult,
        output_path: str,
    ) -> str:
        """Generate a structured JSON analysis report.

        Args:
            result: The BinaryAnalysisResult to report.
            output_path: Filesystem path for the output JSON file.

        Returns:
            The absolute path of the generated report.
        """
        report_data: dict[str, Any] = {
            "report_type": "morph_binary_analysis",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "binary_info": {
                "path": result.info.path,
                "size": result.info.size,
                "format": result.info.format.value,
                "arch": result.info.arch,
                "bits": result.info.bits,
                "endian": result.info.endian,
                "entry_point": result.info.entry_point,
                "md5": result.info.md5,
                "sha256": result.info.sha256,
            },
            "risk_score": result.risk_score,
            "packer_detected": result.packer_detected,
            "sections": [
                {
                    "name": s.name,
                    "offset": s.offset,
                    "size": s.size,
                    "vaddr": s.vaddr,
                    "flags": s.flags,
                    "entropy": round(s.entropy, 4),
                    "type_guess": s.type_guess,
                }
                for s in result.sections
            ],
            "symbols": [
                {
                    "name": sym.name,
                    "value": sym.value,
                    "size": sym.size,
                    "type": sym.type,
                    "bind": sym.bind,
                    "section": sym.section,
                }
                for sym in result.symbols
            ],
            "imports": [
                {
                    "library": imp.library,
                    "function": imp.function,
                    "address": imp.address,
                    "category": imp.category.value,
                }
                for imp in result.imports
            ],
            "strings": {
                "total_count": len(result.strings),
                "by_category": self._strings_by_category(result.strings),
                "items": [
                    {
                        "offset": s.offset,
                        "encoding": s.encoding,
                        "value": s.value,
                        "category": s.category.value if isinstance(s.category, StringCategory) else str(s.category),
                    }
                    for s in result.strings
                ],
            },
            "shellcode_indicators": [
                {
                    "offset": ind.offset,
                    "pattern_name": ind.pattern_name,
                    "description": ind.description,
                    "confidence": round(ind.confidence, 3),
                }
                for ind in result.shellcode_indicators
            ],
            "cfg": {
                "block_count": len(result.cfg.blocks),
                "edge_count": len(result.cfg.edges),
                "cyclomatic_complexity": result.cfg.cyclomatic_complexity,
                "function_count": len(result.cfg.entry_points),
                "entry_points": result.cfg.entry_points,
            },
            "entropy_map": {
                "total_points": len(result.entropy_map),
                "data": [
                    {"offset": off, "entropy": round(ent, 4)}
                    for off, ent in result.entropy_map
                ],
            },
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        return str(path.resolve())

    # ------------------------------------------------------------------ #
    #  HTML section builders
    # ------------------------------------------------------------------ #

    @staticmethod
    def _html_binary_info(info: BinaryInfo) -> str:
        """Generate HTML for binary information panel."""
        return f"""
        <div class="header-panel">
          <h3>Binary Information</h3>
          <div class="meta-row"><span class="meta-label">File:</span><span class="meta-value mono">{html.escape(info.path)}</span></div>
          <div class="meta-row"><span class="meta-label">Size:</span><span class="meta-value">{info.size:,} bytes ({info.size / 1024:.1f} KiB)</span></div>
          <div class="meta-row"><span class="meta-label">Format:</span><span class="meta-value">{html.escape(info.format.value.upper())}</span></div>
          <div class="meta-row"><span class="meta-label">Architecture:</span><span class="meta-value">{html.escape(info.arch)} ({info.bits}-bit, {info.endian})</span></div>
          <div class="meta-row"><span class="meta-label">Entry Point:</span><span class="meta-value mono">0x{info.entry_point:x}</span></div>
          {"<div class='meta-row'><span class='meta-label'>MD5:</span><span class='meta-value mono'>" + html.escape(info.md5) + "</span></div>" if info.md5 else ""}
          {"<div class='meta-row'><span class='meta-label'>SHA-256:</span><span class='meta-value mono'>" + html.escape(info.sha256) + "</span></div>" if info.sha256 else ""}
        </div>
        """

    @staticmethod
    def _html_risk_score(score: float, packer: str) -> str:
        """Generate HTML for the risk score display."""
        if score >= 75:
            css_class = "risk-critical"
            label = "CRITICAL"
        elif score >= 50:
            css_class = "risk-high"
            label = "HIGH"
        elif score >= 25:
            css_class = "risk-medium"
            label = "MEDIUM"
        else:
            css_class = "risk-low"
            label = "LOW"

        packer_html = ""
        if packer:
            packer_html = (
                f'<p style="color: var(--accent-red); margin-top: 0.5rem;">'
                f'Packer Detected: <strong>{html.escape(packer)}</strong></p>'
            )

        return f"""
        <div class="risk-score {css_class}">
          Risk Score: {score:.1f}/100.0 ({label})
          {packer_html}
        </div>
        """

    @staticmethod
    def _html_summary_cards(result: BinaryAnalysisResult) -> str:
        """Generate HTML summary cards."""
        suspicious_imports = sum(
            1 for imp in result.imports
            if imp.category.value != "general"
        )
        interesting_strings = sum(
            1 for s in result.strings
            if (isinstance(s.category, StringCategory) and s.category != StringCategory.GENERAL)
            or (isinstance(s.category, str) and s.category != "general")
        )

        return f"""
        <div class="summary-grid">
          <div class="summary-card">
            <div class="number">{len(result.sections)}</div>
            <div class="label">Sections</div>
          </div>
          <div class="summary-card">
            <div class="number">{len(result.imports)}</div>
            <div class="label">Imports ({suspicious_imports} suspicious)</div>
          </div>
          <div class="summary-card">
            <div class="number">{len(result.strings)}</div>
            <div class="label">Strings ({interesting_strings} interesting)</div>
          </div>
          <div class="summary-card">
            <div class="number">{len(result.shellcode_indicators)}</div>
            <div class="label">Shellcode Indicators</div>
          </div>
          <div class="summary-card">
            <div class="number">{len(result.cfg.blocks)}</div>
            <div class="label">CFG Blocks</div>
          </div>
          <div class="summary-card">
            <div class="number">{result.cfg.cyclomatic_complexity}</div>
            <div class="label">Cyclomatic Complexity</div>
          </div>
        </div>
        """

    @staticmethod
    def _html_sections(sections: list[SectionInfo]) -> str:
        """Generate HTML for the section table."""
        rows: list[str] = []
        for sec in sections:
            # Entropy colour
            if sec.entropy >= 7.5:
                ent_colour = "var(--accent-red)"
            elif sec.entropy >= 7.0:
                ent_colour = "var(--accent-orange)"
            elif sec.entropy >= 6.5:
                ent_colour = "var(--accent-yellow)"
            elif sec.entropy >= 4.5:
                ent_colour = "var(--accent-cyan)"
            else:
                ent_colour = "var(--accent-green)"

            bar_width = int(min(sec.entropy / 8.0, 1.0) * 100)

            rows.append(f"""
            <tr>
              <td class="mono">{html.escape(sec.name or '<unnamed>')}</td>
              <td class="mono">0x{sec.offset:x}</td>
              <td>{sec.size:,}</td>
              <td class="mono">0x{sec.vaddr:x}</td>
              <td>{html.escape(sec.flags)}</td>
              <td style="color: {ent_colour};">{sec.entropy:.3f}</td>
              <td>
                <span class="entropy-bar-bg">
                  <span class="entropy-bar" style="width: {bar_width}px; background: {ent_colour};"></span>
                </span>
              </td>
              <td>{html.escape(sec.type_guess)}</td>
            </tr>
            """)

        return f"""
        <h2>Sections</h2>
        <table>
          <thead>
            <tr><th>Name</th><th>Offset</th><th>Size</th><th>VAddr</th><th>Flags</th><th>Entropy</th><th>Entropy Bar</th><th>Type</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """

    @staticmethod
    def _html_imports(imports: list[ImportInfo]) -> str:
        """Generate HTML for the import table."""
        # Sort by category (suspicious first)
        category_priority = {
            "process_injection": 0, "code_injection": 1, "keylogging": 2,
            "anti_debug": 3, "anti_vm": 4, "privilege": 5,
            "network": 6, "crypto": 7, "registry": 8,
            "file_operations": 9, "general": 10,
        }
        sorted_imports = sorted(
            imports,
            key=lambda x: category_priority.get(x.category.value, 10),
        )

        rows: list[str] = []
        for imp in sorted_imports:
            cat = imp.category.value
            if cat in ("process_injection", "keylogging"):
                tag_class = "tag-critical"
            elif cat in ("code_injection", "privilege"):
                tag_class = "tag-high"
            elif cat in ("anti_debug", "anti_vm", "network"):
                tag_class = "tag-medium"
            elif cat in ("file_operations", "registry", "crypto"):
                tag_class = "tag-low"
            else:
                tag_class = "tag-info"

            rows.append(f"""
            <tr>
              <td>{html.escape(imp.library)}</td>
              <td class="mono">{html.escape(imp.function)}</td>
              <td><span class="tag {tag_class}">{html.escape(cat)}</span></td>
              <td class="mono">{'0x' + format(imp.address, 'x') if imp.address else '-'}</td>
            </tr>
            """)

        return f"""
        <h2>Imports ({len(imports)} total)</h2>
        <table>
          <thead>
            <tr><th>Library</th><th>Function</th><th>Category</th><th>Address</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """

    @staticmethod
    def _html_strings(strings: list[StringResult]) -> str:
        """Generate HTML for extracted strings."""
        # Show up to 500 strings
        display_list = strings[:500]

        rows: list[str] = []
        for s in display_list:
            cat = s.category.value if isinstance(s.category, StringCategory) else str(s.category)
            if cat in ("suspicious", "crypto"):
                tag_class = "tag-critical"
            elif cat in ("url", "ip_address", "domain"):
                tag_class = "tag-high"
            elif cat in ("file_path", "registry", "email"):
                tag_class = "tag-medium"
            elif cat == "base64":
                tag_class = "tag-low"
            else:
                tag_class = "tag-info"

            display_val = s.value[:200]
            if len(s.value) > 200:
                display_val += "..."

            rows.append(f"""
            <tr>
              <td class="mono">0x{s.offset:x}</td>
              <td>{html.escape(s.encoding)}</td>
              <td><span class="tag {tag_class}">{html.escape(cat)}</span></td>
              <td class="mono">{html.escape(display_val)}</td>
            </tr>
            """)

        note = ""
        if len(strings) > 500:
            note = f'<p style="color: var(--text-secondary);">Showing 500 of {len(strings)} strings. See JSON report for complete listing.</p>'

        return f"""
        <h2>Extracted Strings ({len(strings)} total)</h2>
        {note}
        <table>
          <thead>
            <tr><th>Offset</th><th>Encoding</th><th>Category</th><th>Value</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """

    @staticmethod
    def _html_shellcode(indicators: list[ShellcodeIndicator]) -> str:
        """Generate HTML for shellcode indicators."""
        rows: list[str] = []
        for ind in indicators:
            conf = ind.confidence
            if conf >= 0.8:
                tag_class = "tag-critical"
            elif conf >= 0.6:
                tag_class = "tag-high"
            elif conf >= 0.4:
                tag_class = "tag-medium"
            else:
                tag_class = "tag-low"

            rows.append(f"""
            <tr>
              <td class="mono">0x{ind.offset:x}</td>
              <td>{html.escape(ind.pattern_name)}</td>
              <td><span class="tag {tag_class}">{conf:.0%}</span></td>
              <td class="shellcode-desc">{html.escape(ind.description[:300])}</td>
            </tr>
            """)

        return f"""
        <h2>Shellcode Indicators ({len(indicators)})</h2>
        <table>
          <thead>
            <tr><th>Offset</th><th>Pattern</th><th>Confidence</th><th>Description</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
        """

    @staticmethod
    def _html_cfg(cfg: CFGResult) -> str:
        """Generate HTML for CFG summary."""
        # Complexity assessment
        cc = cfg.cyclomatic_complexity
        if cc <= 10:
            complexity_label = "Simple"
            complexity_colour = "var(--accent-green)"
        elif cc <= 20:
            complexity_label = "Moderate"
            complexity_colour = "var(--accent-yellow)"
        elif cc <= 50:
            complexity_label = "Complex"
            complexity_colour = "var(--accent-orange)"
        else:
            complexity_label = "Very Complex"
            complexity_colour = "var(--accent-red)"

        return f"""
        <h2>Control Flow Graph</h2>
        <div class="header-panel">
          <div class="meta-row"><span class="meta-label">Basic Blocks:</span><span class="meta-value">{len(cfg.blocks)}</span></div>
          <div class="meta-row"><span class="meta-label">Edges:</span><span class="meta-value">{len(cfg.edges)}</span></div>
          <div class="meta-row"><span class="meta-label">Cyclomatic Complexity:</span><span class="meta-value" style="color: {complexity_colour};">{cc} ({complexity_label})</span></div>
          <div class="meta-row"><span class="meta-label">Functions:</span><span class="meta-value">{len(cfg.entry_points)}</span></div>
        </div>
        """

    # ------------------------------------------------------------------ #
    #  JSON helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _strings_by_category(strings: list[StringResult]) -> dict[str, int]:
        """Count strings by category for JSON output."""
        counts: dict[str, int] = {}
        for s in strings:
            cat = s.category.value if isinstance(s.category, StringCategory) else str(s.category)
            counts[cat] = counts.get(cat, 0) + 1
        return counts
