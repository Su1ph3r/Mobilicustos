"""Exports router for generating reports."""

import io
import json
import logging
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding, MobileApp, Scan

router = APIRouter()
logger = logging.getLogger(__name__)


def _sanitize_filename(name: str) -> str:
    """Sanitize a string for safe use in Content-Disposition filenames."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


# ---------------------------------------------------------------------------
# Phase 0A: Severity constants and sort helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


def _severity_sort_key(finding):
    """Sort key for findings: severity (critical first), then created_at ASC.

    Works on both ORM objects and dicts.
    """
    if isinstance(finding, dict):
        sev = finding.get("severity", "info") or "info"
        created = finding.get("created_at", "") or ""
    else:
        sev = getattr(finding, "severity", "info") or "info"
        created = getattr(finding, "created_at", "") or ""
    return (SEVERITY_ORDER.get(sev, 5), str(created))


def _apply_severity_order(query):
    """Apply severity ordering to a SQLAlchemy query: critical first, then created_at DESC."""
    severity_order = func.array_position(
        ["critical", "high", "medium", "low", "info"],
        func.coalesce(Finding.severity, "info"),
    )
    return query.order_by(severity_order, Finding.created_at.desc())


# ---------------------------------------------------------------------------
# Phase 0B: Color constants
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_COLORS_RGB = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (37, 99, 235),
    "info": (107, 114, 128),
}

SEVERITY_BG_COLORS = {
    "critical": "#fef2f2",
    "high": "#fff7ed",
    "medium": "#fefce8",
    "low": "#eff6ff",
    "info": "#f9fafb",
}

COMMAND_TYPE_COLORS = {
    "adb": "#4caf50",
    "frida": "#ff9800",
    "bash": "#607d8b",
    "drozer": "#9c27b0",
    "objection": "#2196f3",
    "android": "#3ddc84",
    "ios": "#007aff",
    "gradle": "#02303a",
}

RESOURCE_TYPE_COLORS = {
    "documentation": "#1976d2",
    "blog": "#e91e63",
    "video": "#f44336",
    "github": "#24292e",
    "tool": "#00bcd4",
}

# Google Fonts link for generated HTML reports
_GOOGLE_FONTS_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link href="https://fonts.googleapis.com/css2?family=Jost:wght@300;400;500;600;700;800'
    '&family=Source+Code+Pro:wght@400;500;600;700&display=swap" rel="stylesheet">'
)
_FONT_BODY = "'Jost', -apple-system, BlinkMacSystemFont, sans-serif"
_FONT_MONO = "'Source Code Pro', 'JetBrains Mono', monospace"


# ---------------------------------------------------------------------------
# Phase 0C: Full finding serializer
# ---------------------------------------------------------------------------

def _serialize_finding(f) -> dict:
    """Convert an ORM Finding object to a dict with all fields."""
    return {
        "finding_id": f.finding_id,
        "app_id": f.app_id,
        "scan_id": str(f.scan_id) if f.scan_id else None,
        "tool": f.tool,
        "tool_sources": f.tool_sources or [],
        "platform": f.platform,
        "severity": f.severity,
        "status": f.status,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "impact": f.impact,
        "remediation": f.remediation,
        "resource_type": f.resource_type,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "code_snippet": f.code_snippet,
        "poc_evidence": f.poc_evidence,
        "poc_verification": f.poc_verification,
        "poc_commands": f.poc_commands or [],
        "poc_frida_script": f.poc_frida_script,
        "poc_screenshot_path": f.poc_screenshot_path,
        "remediation_commands": f.remediation_commands or [],
        "remediation_code": f.remediation_code or {},
        "remediation_resources": f.remediation_resources or [],
        "risk_score": float(f.risk_score) if f.risk_score is not None else None,
        "cvss_score": float(f.cvss_score) if f.cvss_score is not None else None,
        "cvss_vector": f.cvss_vector,
        "cwe_id": f.cwe_id,
        "cwe_name": f.cwe_name,
        "owasp_masvs_category": f.owasp_masvs_category,
        "owasp_masvs_control": f.owasp_masvs_control,
        "owasp_mastg_test": f.owasp_mastg_test,
        "canonical_id": f.canonical_id,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


# ---------------------------------------------------------------------------
# Phase 0D: HTML building blocks
# ---------------------------------------------------------------------------

def _hex_to_rgba(hex_color: str, alpha: float = 0.15) -> str:
    """Convert a hex color to a CSS rgba string."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _build_commands_html(commands: list, label: str) -> str:
    """Render typed commands (PoC or remediation) with type badges."""
    from html import escape

    if not commands:
        return ""
    items = ""
    for cmd in commands:
        if isinstance(cmd, dict):
            cmd_type = cmd.get("type", "bash")
            cmd_text = cmd.get("command", str(cmd))
        else:
            cmd_type = "bash"
            cmd_text = str(cmd)
        color = COMMAND_TYPE_COLORS.get(cmd_type, "#607d8b")
        items += (
            f'<div style="margin-bottom:8px;">'
            f'<span style="display:inline-block;background:{color};color:#fff;'
            f'padding:1px 6px;border-radius:3px;font-size:11px;margin-right:6px;">'
            f'{escape(cmd_type)}</span>'
            f'<pre style="display:inline;background:#1e293b;color:#e2e8f0;'
            f'padding:4px 8px;border-radius:3px;font-size:12px;font-family:{_FONT_MONO};">'
            f'{escape(cmd_text)}</pre></div>'
        )
    return f'<div style="margin-top:8px;"><strong>{escape(label)}:</strong>{items}</div>'


def _build_resources_html(resources: list) -> str:
    """Render remediation resource links."""
    from html import escape

    if not resources:
        return ""
    items = ""
    for res in resources:
        if isinstance(res, dict):
            res_type = res.get("type", "documentation")
            title = res.get("title", res.get("url", "Link"))
            url = res.get("url", "#")
        else:
            res_type = "documentation"
            title = str(res)
            url = str(res)
        color = RESOURCE_TYPE_COLORS.get(res_type, "#1976d2")
        safe_url = url if url.startswith(("http://", "https://", "/")) else "#"
        items += (
            f'<div style="margin-bottom:4px;">'
            f'<span style="display:inline-block;background:{_hex_to_rgba(color)};'
            f'color:{color};padding:1px 6px;border-radius:3px;font-size:11px;'
            f'margin-right:6px;">{escape(res_type)}</span>'
            f'<a href="{escape(safe_url)}" target="_blank" '
            f'style="color:#2563eb;text-decoration:none;">{escape(title)}</a></div>'
        )
    return f'<div style="margin-top:8px;"><strong>Resources:</strong>{items}</div>'


def _build_code_tabs_html(remediation_code: dict) -> str:
    """Render code examples by language."""
    from html import escape

    if not remediation_code:
        return ""
    tabs = ""
    for lang, code in remediation_code.items():
        tabs += (
            f'<div style="margin-top:8px;">'
            f'<span style="display:inline-block;background:#e5e7eb;color:#374151;'
            f'padding:2px 8px;border-radius:4px 4px 0 0;font-size:12px;'
            f'font-weight:600;">{escape(lang)}</span>'
            f'<pre style="background:#1e293b;color:#e2e8f0;padding:12px;'
            f'border-radius:0 4px 4px 4px;font-size:12px;margin:0;overflow-x:auto;'
            f'font-family:{_FONT_MONO};">{escape(str(code))}</pre></div>'
        )
    return f'<div style="margin-top:8px;"><strong>Code Examples:</strong>{tabs}</div>' if tabs else ""


def _build_finding_accordion_html(f: dict, index: int) -> str:
    """Build a full accordion item for a finding, matching FindingDetail.vue layout."""
    from html import escape

    sev = f.get("severity", "info") or "info"
    sev_color = SEVERITY_COLORS.get(sev, "#6b7280")
    fid = f"finding-{index}"

    # --- Tool sources badges ---
    tool_sources = f.get("tool_sources") or []
    tools_html = ""
    if tool_sources:
        badges = "".join(
            f'<span style="display:inline-block;padding:4px 10px;border-radius:6px;'
            f'font-size:12px;font-weight:500;background:rgba(99,102,241,0.1);'
            f'color:#6366f1;border:1px solid rgba(99,102,241,0.2);margin-right:4px;">'
            f'{escape(str(t).replace("_", " ").title())}</span>'
            for t in tool_sources
        )
        tools_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Detected By</strong>'
            f'<div style="margin-top:4px;">{badges}</div></div>'
        )

    # --- Description ---
    desc_html = (
        f'<div style="margin-bottom:12px;">'
        f'<strong class="section-label">Description</strong>'
        f'<p style="margin:4px 0 0;line-height:1.7;">'
        f'{escape(f.get("description", "") or "No description available")}</p></div>'
    )

    # --- Location Details grid ---
    loc_items = []
    for label, key in [
        ("File Path", "file_path"),
        ("Line Number", "line_number"),
        ("Category", "category"),
        ("Platform", "platform"),
        ("Tool", "tool"),
    ]:
        val = f.get(key)
        if val is not None:
            display = str(val).replace("_", " ").title() if key == "tool" else str(val)
            loc_items.append(
                f'<div class="grid-item">'
                f'<span class="grid-label">{label}</span>'
                f'<span class="grid-value">{escape(display)}</span></div>'
            )
    cwe_id = f.get("cwe_id")
    if cwe_id:
        cwe_num = cwe_id.replace("CWE-", "")
        cwe_name = f.get("cwe_name")
        cwe_display = f'{escape(cwe_id)}{" - " + escape(cwe_name) if cwe_name else ""}'
        loc_items.append(
            f'<div class="grid-item">'
            f'<span class="grid-label">CWE</span>'
            f'<a href="https://cwe.mitre.org/data/definitions/{escape(cwe_num)}.html" '
            f'target="_blank" style="font-size:13px;color:#2563eb;text-decoration:none;">'
            f'{cwe_display}</a></div>'
        )
    loc_html = ""
    if loc_items:
        loc_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Location Details</strong>'
            f'<div class="detail-grid" style="margin-top:4px;">'
            f'{"".join(loc_items)}</div></div>'
        )

    # --- Code Snippet ---
    code_html = ""
    if f.get("code_snippet"):
        code_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Code Snippet</strong>'
            f'<pre class="code-block">{escape(f["code_snippet"])}</pre></div>'
        )

    # --- Verification Command ---
    verify_html = ""
    if f.get("poc_verification"):
        verify_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Verification Command</strong>'
            f'<pre class="code-block">{escape(f["poc_verification"])}</pre></div>'
        )

    # --- PoC Evidence ---
    poc_parts = []
    if f.get("poc_evidence"):
        poc_parts.append(
            f'<p style="margin:4px 0 8px;line-height:1.6;">{escape(f["poc_evidence"])}</p>'
        )
    if f.get("poc_screenshot_path"):
        poc_parts.append(
            f'<p style="font-size:12px;color:#6b7280;">Screenshot: '
            f'{escape(f["poc_screenshot_path"])}</p>'
        )
    if f.get("poc_commands"):
        poc_parts.append(_build_commands_html(f["poc_commands"], "PoC Commands"))
    if f.get("poc_frida_script"):
        poc_parts.append(
            f'<div style="margin-top:8px;"><strong>Frida Script:</strong>'
            f'<pre class="code-block">{escape(f["poc_frida_script"])}</pre></div>'
        )
    poc_html = ""
    if poc_parts:
        poc_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">PoC Evidence</strong>'
            f'{"".join(poc_parts)}</div>'
        )

    # --- Impact ---
    impact_html = ""
    if f.get("impact"):
        impact_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Impact</strong>'
            f'<p style="margin:4px 0 0;line-height:1.7;">{escape(f["impact"])}</p></div>'
        )

    # --- Remediation ---
    rem_parts = []
    if f.get("remediation"):
        rem_parts.append(
            f'<p style="margin:4px 0 8px;line-height:1.7;">{escape(f["remediation"])}</p>'
        )
    owasp_links = []
    if f.get("owasp_masvs_category"):
        owasp_links.append(f'MASVS: {escape(f["owasp_masvs_category"])}')
    if f.get("owasp_masvs_control"):
        owasp_links.append(f'Control: {escape(f["owasp_masvs_control"])}')
    if f.get("owasp_mastg_test"):
        owasp_links.append(f'MASTG: {escape(f["owasp_mastg_test"])}')
    if owasp_links:
        rem_parts.append(
            f'<p style="font-size:12px;color:#6b7280;">{" | ".join(owasp_links)}</p>'
        )
    if f.get("remediation_commands"):
        rem_parts.append(
            _build_commands_html(f["remediation_commands"], "Remediation Commands")
        )
    if f.get("remediation_code"):
        rem_parts.append(_build_code_tabs_html(f["remediation_code"]))
    if f.get("remediation_resources"):
        rem_parts.append(_build_resources_html(f["remediation_resources"]))
    rem_html = ""
    if rem_parts:
        rem_html = (
            f'<div style="margin-bottom:12px;">'
            f'<strong class="section-label">Remediation</strong>'
            f'{"".join(rem_parts)}</div>'
        )

    # --- Metadata grid ---
    meta_items = []
    for label, key in [
        ("Finding ID", "finding_id"),
        ("First Seen", "first_seen"),
        ("Last Seen", "last_seen"),
        ("Canonical ID", "canonical_id"),
    ]:
        val = f.get(key)
        if val:
            meta_items.append(
                f'<div class="grid-item">'
                f'<span class="grid-label">{label}</span>'
                f"<span class=\"grid-value\" style=\"font-family:{_FONT_MONO};font-size:12px;"
                f'word-break:break-all;">{escape(str(val))}</span></div>'
            )
    if f.get("cvss_score"):
        meta_items.append(
            f'<div class="grid-item">'
            f'<span class="grid-label">CVSS Score</span>'
            f'<span class="grid-value" style="font-weight:600;color:{sev_color};">'
            f'{f["cvss_score"]}</span></div>'
        )
    if f.get("cvss_vector"):
        meta_items.append(
            f'<div class="grid-item">'
            f'<span class="grid-label">CVSS Vector</span>'
            f"<span class=\"grid-value\" style=\"font-family:{_FONT_MONO};font-size:12px;"
            f'word-break:break-all;">{escape(str(f["cvss_vector"]))}</span></div>'
        )
    if f.get("risk_score"):
        meta_items.append(
            f'<div class="grid-item">'
            f'<span class="grid-label">Risk Score</span>'
            f'<span class="grid-value">{f["risk_score"]}</span></div>'
        )
    meta_html = ""
    if meta_items:
        meta_html = (
            f'<div style="margin-bottom:0;">'
            f'<strong class="section-label">Metadata</strong>'
            f'<div class="detail-grid" style="margin-top:4px;">'
            f'{"".join(meta_items)}</div></div>'
        )

    # --- Accordion assembly ---
    return (
        f'<div class="accordion-item" style="border:1px solid #e5e7eb;'
        f'border-left:4px solid {sev_color};border-radius:4px;'
        f'margin-bottom:12px;overflow:hidden;">'
        f'<div class="accordion-header" onclick="toggleAccordion(\'{fid}\')" '
        f'style="display:flex;align-items:center;justify-content:space-between;'
        f'padding:12px 16px;cursor:pointer;'
        f'background:{_hex_to_rgba(sev_color, 0.05)};user-select:none;">'
        f'<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">'
        f'<span style="font-weight:600;color:#1f2937;">{index}.</span>'
        f'<span style="background:{sev_color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:600;flex-shrink:0;">'
        f'{escape(sev.upper())}</span>'
        f'<span style="font-weight:500;color:#1f2937;white-space:nowrap;'
        f'overflow:hidden;text-overflow:ellipsis;">{escape(f.get("title", ""))}</span>'
        f'</div>'
        f'<span class="accordion-arrow" id="arrow-{fid}" '
        f'style="transition:transform 0.2s;font-size:12px;color:#9ca3af;'
        f'flex-shrink:0;margin-left:8px;">&#9660;</span>'
        f'</div>'
        f'<div class="accordion-body" id="{fid}" '
        f'style="display:none;padding:16px;border-top:1px solid #e5e7eb;">'
        f'{tools_html}{desc_html}{loc_html}{code_html}{verify_html}'
        f'{poc_html}{impact_html}{rem_html}{meta_html}'
        f'</div></div>'
    )


def _accordion_js_css() -> str:
    """JS toggle function + expand/collapse all buttons + print media query."""
    return """<style>
.section-label {
    display:block;font-size:11px;font-weight:600;text-transform:uppercase;
    color:#6b7280;letter-spacing:0.03em;margin-bottom:4px;
}
.detail-grid {
    display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;
}
.grid-item {
    display:flex;flex-direction:column;gap:2px;padding:8px;
    background:#f9fafb;border-radius:4px;
}
.grid-label {
    font-size:11px;font-weight:600;color:#9ca3af;
    text-transform:uppercase;letter-spacing:0.03em;
}
.grid-value {
    font-size:13px;color:#1f2937;word-break:break-word;
}
.code-block {
    background:#1e293b;color:#e2e8f0;padding:12px;border-radius:4px;
    font-size:12px;overflow-x:auto;white-space:pre-wrap;
    word-break:break-word;margin:4px 0 0;font-family:'Source Code Pro','JetBrains Mono',monospace;
}
@media print {
    .accordion-body { display: block !important; }
    .accordion-header { cursor: default !important; }
    .no-print { display: none !important; }
}
</style>
<script>
function toggleAccordion(id) {
    var el = document.getElementById(id);
    var arrow = document.getElementById('arrow-' + id);
    if (el.style.display === 'none') {
        el.style.display = 'block';
        if (arrow) arrow.style.transform = 'rotate(180deg)';
    } else {
        el.style.display = 'none';
        if (arrow) arrow.style.transform = 'rotate(0deg)';
    }
}
function expandAll() {
    document.querySelectorAll('.accordion-body').forEach(function(el) {
        el.style.display = 'block';
    });
    document.querySelectorAll('.accordion-arrow').forEach(function(el) {
        el.style.transform = 'rotate(180deg)';
    });
}
function collapseAll() {
    document.querySelectorAll('.accordion-body').forEach(function(el) {
        el.style.display = 'none';
    });
    document.querySelectorAll('.accordion-arrow').forEach(function(el) {
        el.style.transform = 'rotate(0deg)';
    });
}
</script>"""


# ---------------------------------------------------------------------------
# Phase 0E: PDF building blocks
# ---------------------------------------------------------------------------

def _pdf_safe_text(text: str) -> str:
    """Strip characters outside the latin-1 range that Helvetica cannot render."""
    if not text:
        return ""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _pdf_section(pdf, label: str, text: str):
    """Render a labeled text section in the PDF, no truncation."""
    if not text:
        return
    text = _pdf_safe_text(text)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 6, label.upper(), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(55, 65, 81)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(w=0, h=5, text=text, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _pdf_code_block(pdf, label: str, code: str):
    """Render a labeled code block with gray background in the PDF."""
    if not code:
        return
    code = _pdf_safe_text(code)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 6, label.upper(), new_x="LMARGIN", new_y="NEXT")
    pdf.set_fill_color(243, 244, 246)
    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(30, 41, 59)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(w=0, h=4, text=code, new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.set_fill_color(255, 255, 255)
    pdf.ln(2)


def _pdf_commands(pdf, commands: list, label: str):
    """Render typed commands in PDF."""
    if not commands:
        return
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 6, label.upper(), new_x="LMARGIN", new_y="NEXT")
    for cmd in commands:
        if isinstance(cmd, dict):
            cmd_type = cmd.get("type", "bash")
            cmd_text = cmd.get("command", str(cmd))
        else:
            cmd_type = "bash"
            cmd_text = str(cmd)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(20, 5, f"[{cmd_type}]")
        pdf.set_fill_color(243, 244, 246)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(30, 41, 59)
        pdf.multi_cell(w=0, h=4, text=_pdf_safe_text(cmd_text), new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_fill_color(255, 255, 255)
    pdf.ln(2)


def _pdf_safe_dict(d: dict) -> dict:
    """Deep-sanitize a dict so all string values are latin-1 safe for fpdf2."""
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = _pdf_safe_text(v)
        elif isinstance(v, dict):
            out[k] = _pdf_safe_dict(v)
        elif isinstance(v, list):
            out[k] = [
                _pdf_safe_dict(i) if isinstance(i, dict)
                else _pdf_safe_text(i) if isinstance(i, str)
                else i
                for i in v
            ]
        else:
            out[k] = v
    return out


def _render_finding_to_pdf(pdf, f: dict, index: int):
    """Render a full finding to PDF, matching UI layout, no truncation."""
    f = _pdf_safe_dict(f)
    sev = f.get("severity", "info") or "info"
    r, g, b = SEVERITY_COLORS_RGB.get(sev, (107, 114, 128))

    if pdf.get_y() > 250:
        pdf.add_page()

    # Finding header
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(31, 41, 55)
    pdf.cell(0, 8, f"{index}. {f.get('title', '')}", new_x="LMARGIN", new_y="NEXT")

    # Severity + meta line
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(r, g, b)
    pdf.cell(25, 6, sev.upper())
    pdf.set_text_color(107, 114, 128)
    pdf.set_font("Helvetica", "", 9)
    meta_parts = []
    if f.get("category"):
        meta_parts.append(f["category"])
    if f.get("cwe_id"):
        cwe_str = f["cwe_id"]
        if f.get("cwe_name"):
            cwe_str += f" - {f['cwe_name']}"
        meta_parts.append(cwe_str)
    if f.get("cvss_score"):
        meta_parts.append(f"CVSS: {f['cvss_score']}")
    if f.get("cvss_vector"):
        meta_parts.append(f["cvss_vector"])
    pdf.cell(0, 6, " | ".join(meta_parts), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Tool sources
    tool_sources = f.get("tool_sources") or []
    if tool_sources:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 6, "DETECTED BY", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(55, 65, 81)
        pdf.cell(
            0, 5,
            ", ".join(str(t).replace("_", " ").title() for t in tool_sources),
            new_x="LMARGIN", new_y="NEXT",
        )
        pdf.ln(2)

    # Description
    _pdf_section(pdf, "Description", f.get("description", ""))

    # Location details
    loc_parts = []
    if f.get("file_path"):
        loc = f"File: {f['file_path']}"
        if f.get("line_number"):
            loc += f" (line {f['line_number']})"
        loc_parts.append(loc)
    if f.get("platform"):
        loc_parts.append(f"Platform: {f['platform']}")
    if f.get("tool"):
        loc_parts.append(f"Tool: {f['tool']}")
    if loc_parts:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 6, "LOCATION DETAILS", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(55, 65, 81)
        for lp in loc_parts:
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 5, lp, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Code Snippet
    _pdf_code_block(pdf, "Code Snippet", f.get("code_snippet", ""))

    # Verification Command
    _pdf_code_block(pdf, "Verification Command", f.get("poc_verification", ""))

    # PoC Evidence
    has_poc = (
        f.get("poc_evidence")
        or f.get("poc_commands")
        or f.get("poc_frida_script")
        or f.get("poc_screenshot_path")
    )
    if has_poc:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 6, "POC EVIDENCE", new_x="LMARGIN", new_y="NEXT")
        if f.get("poc_evidence"):
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(55, 65, 81)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                w=0, h=5, text=f["poc_evidence"],
                new_x="LMARGIN", new_y="NEXT",
            )
        if f.get("poc_screenshot_path"):
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(107, 114, 128)
            pdf.cell(
                0, 5, f"Screenshot: {f['poc_screenshot_path']}",
                new_x="LMARGIN", new_y="NEXT",
            )
        _pdf_commands(pdf, f.get("poc_commands") or [], "PoC Commands")
        _pdf_code_block(pdf, "Frida Script", f.get("poc_frida_script", ""))

    # Impact
    _pdf_section(pdf, "Impact", f.get("impact", ""))

    # Remediation
    has_rem = (
        f.get("remediation")
        or f.get("remediation_commands")
        or f.get("remediation_code")
        or f.get("remediation_resources")
    )
    if has_rem:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 6, "REMEDIATION", new_x="LMARGIN", new_y="NEXT")
        if f.get("remediation"):
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(55, 65, 81)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                w=0, h=5, text=f["remediation"],
                new_x="LMARGIN", new_y="NEXT",
            )
            pdf.ln(1)

        # OWASP links
        owasp_parts = []
        if f.get("owasp_masvs_category"):
            owasp_parts.append(f"MASVS: {f['owasp_masvs_category']}")
        if f.get("owasp_masvs_control"):
            owasp_parts.append(f"Control: {f['owasp_masvs_control']}")
        if f.get("owasp_mastg_test"):
            owasp_parts.append(f"MASTG: {f['owasp_mastg_test']}")
        if owasp_parts:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(107, 114, 128)
            pdf.cell(0, 5, " | ".join(owasp_parts), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

        _pdf_commands(pdf, f.get("remediation_commands") or [], "Remediation Commands")

        for lang, code in (f.get("remediation_code") or {}).items():
            _pdf_code_block(pdf, f"Code ({lang})", str(code))

        resources = f.get("remediation_resources") or []
        if resources:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(107, 114, 128)
            pdf.cell(0, 6, "RESOURCES", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(37, 99, 235)
            for res in resources:
                if isinstance(res, dict):
                    line = f"- {res.get('title', res.get('url', ''))}: {res.get('url', '')}"
                else:
                    line = f"- {str(res)}"
                pdf.set_x(pdf.l_margin)
                pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    # Metadata
    meta_items = []
    if f.get("finding_id"):
        meta_items.append(f"Finding ID: {f['finding_id']}")
    if f.get("first_seen"):
        meta_items.append(f"First Seen: {f['first_seen']}")
    if f.get("last_seen"):
        meta_items.append(f"Last Seen: {f['last_seen']}")
    if f.get("canonical_id"):
        meta_items.append(f"Canonical ID: {f['canonical_id']}")
    if f.get("risk_score"):
        meta_items.append(f"Risk Score: {f['risk_score']}")
    if meta_items:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 6, "METADATA", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(55, 65, 81)
        for mi in meta_items:
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 4, mi, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Separator
    pdf.set_draw_color(229, 231, 235)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)


# ===========================================================================
# Export endpoint
# ===========================================================================

@router.get("/findings/{app_id}")
async def export_findings(
    app_id: str,
    format: str = Query("json", pattern="^(json|csv|sarif|html|pdf)$"),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Export findings for an app in various formats.

    Use app_id='all' to export findings across all apps.
    """
    app = None

    # Handle 'all' app_id for exporting all findings
    if app_id.lower() != "all":
        # Verify app exists
        result = await db.execute(
            select(MobileApp).where(MobileApp.app_id == app_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

    # Get findings
    if app_id.lower() == "all":
        query = select(Finding)
    else:
        query = select(Finding).where(Finding.app_id == app_id)

    if severity:
        query = query.where(Finding.severity.in_(severity))
    if status:
        query = query.where(Finding.status.in_(status))

    # Phase 1A: Apply severity ordering
    query = _apply_severity_order(query)

    findings_result = await db.execute(query)
    findings = findings_result.scalars().all()

    if format == "json":
        return _export_json(app, findings)
    elif format == "csv":
        return _export_csv(app, findings)
    elif format == "sarif":
        return _export_sarif(app, findings)
    elif format == "html":
        return _export_findings_html(app, findings)
    elif format == "pdf":
        return _export_findings_pdf(app, findings)


# ===========================================================================
# JSON export — Phase 2A: full field parity
# ===========================================================================

def _export_json(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as JSON with all fields."""
    data = {
        "app": {
            "app_id": app.app_id if app else "all",
            "package_name": app.package_name if app else "all_apps",
            "app_name": app.app_name if app else "All Applications",
            "platform": app.platform if app else "mixed",
            "version": app.version_name if app else None,
        } if app else None,
        "exported_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": [_serialize_finding(f) for f in findings],
    }

    filename = (
        f"{_sanitize_filename(app.package_name)}_findings.json"
        if app else "all_findings.json"
    )
    content = json.dumps(data, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ===========================================================================
# CSV export — Phase 2B: expanded columns, no truncation
# ===========================================================================

def _export_csv(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as CSV with all fields, no truncation."""
    import csv

    output = io.StringIO()
    writer = csv.writer(output)

    header = [
        "Finding ID",
        "Title",
        "Severity",
        "Status",
        "Category",
        "Tool",
        "Tool Sources",
        "Platform",
        "File Path",
        "Line",
        "Code Snippet",
        "Resource Type",
        "CWE",
        "CWE Name",
        "CVSS Score",
        "CVSS Vector",
        "Risk Score",
        "MASVS Category",
        "MASVS Control",
        "MASTG Test",
        "Description",
        "Impact",
        "Remediation",
        "PoC Evidence",
        "PoC Verification",
        "PoC Commands",
        "PoC Frida Script",
        "PoC Screenshot Path",
        "Remediation Commands",
        "Remediation Code",
        "Remediation Resources",
        "Canonical ID",
        "First Seen",
        "Last Seen",
        "Created At",
    ]
    if not app:
        header.insert(1, "App ID")
    writer.writerow(header)

    for f in findings:
        row = [
            f.finding_id,
            f.title,
            f.severity,
            f.status,
            f.category,
            f.tool,
            json.dumps(f.tool_sources or []),
            f.platform,
            f.file_path,
            f.line_number,
            f.code_snippet,
            f.resource_type,
            f.cwe_id,
            f.cwe_name,
            float(f.cvss_score) if f.cvss_score else "",
            f.cvss_vector,
            float(f.risk_score) if f.risk_score else "",
            f.owasp_masvs_category,
            f.owasp_masvs_control,
            f.owasp_mastg_test,
            f.description,
            f.impact,
            f.remediation,
            f.poc_evidence,
            f.poc_verification,
            json.dumps(f.poc_commands or []),
            f.poc_frida_script,
            f.poc_screenshot_path,
            json.dumps(f.remediation_commands or []),
            json.dumps(f.remediation_code or {}),
            json.dumps(f.remediation_resources or []),
            f.canonical_id,
            f.first_seen.isoformat() if f.first_seen else "",
            f.last_seen.isoformat() if f.last_seen else "",
            f.created_at.isoformat() if f.created_at else "",
        ]
        if not app:
            row.insert(1, f.app_id)
        writer.writerow(row)

    filename = (
        f"{_sanitize_filename(app.package_name)}_findings.csv"
        if app else "all_findings.csv"
    )
    content = output.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ===========================================================================
# SARIF export (unchanged except findings are now severity-ordered from query)
# ===========================================================================

def _build_rule_tags(finding: Finding) -> list[str]:
    """Build SARIF rule tags from finding metadata."""
    tags = []
    if finding.cwe_id:
        tags.append(f"external/cwe/{finding.cwe_id}")
    if finding.owasp_masvs_category:
        tags.append(f"external/owasp/{finding.owasp_masvs_category}")
    if finding.severity:
        tags.append(f"security/severity/{finding.severity}")
    tags.append("security")
    return tags


def _export_sarif(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings in SARIF format (Static Analysis Results Interchange Format).

    Produces a SARIF 2.1.0 compliant document with enriched metadata including:
    - Full rule descriptions with remediation help text
    - CWE taxonomy references and rule relationships
    - Cross-run fingerprints using canonical IDs
    - Code snippets in location regions
    - CVSS scores and OWASP categories in result properties
    """
    # Collect unique CWE IDs for taxonomy
    cwe_ids_seen: set[str] = set()

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Mobilicustos",
                        "version": "0.1.3",
                        "informationUri": "https://github.com/mobilicustos",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    run = sarif["runs"][0]

    # Build rules and results
    rules_map: dict[str, dict] = {}
    for f in findings:
        rule_id = f.category or f.tool
        if rule_id not in rules_map:
            rule = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.category or f.tool},
                "fullDescription": {"text": f.description[:1000] if f.description else f.title},
                "help": {
                    "text": f.remediation or "No remediation guidance available.",
                    "markdown": f"**Remediation:** {f.remediation}" if f.remediation else "",
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity)
                },
                "properties": {
                    "tags": _build_rule_tags(f),
                },
            }

            # Add CWE relationship
            if f.cwe_id:
                cwe_ids_seen.add(f.cwe_id)
                cwe_num = f.cwe_id.replace("CWE-", "")
                rule["relationships"] = [
                    {
                        "target": {
                            "id": f.cwe_id,
                            "guid": f"cwe-{cwe_num}",
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    }
                ]

            rules_map[rule_id] = rule

        # Build result
        message_parts = [f.title]
        if f.description and f.description != f.title:
            message_parts.append(f.description[:500])
        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {"text": " — ".join(message_parts)},
            "locations": [],
        }

        # Fingerprints for cross-run matching
        if hasattr(f, "canonical_id") and f.canonical_id:
            result["fingerprints"] = {
                "mobilicustos/canonical/v1": f.canonical_id,
            }

        # Location with code snippet
        if f.file_path:
            location: dict = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                }
            }
            region: dict = {}
            if f.line_number:
                region["startLine"] = f.line_number
            if f.code_snippet:
                region["snippet"] = {"text": f.code_snippet[:2000]}
            if region:
                location["physicalLocation"]["region"] = region
            result["locations"].append(location)

        # Result-level properties
        props: dict = {}
        if f.severity:
            props["severity"] = f.severity
        if f.cvss_score is not None:
            props["cvssScore"] = float(f.cvss_score)
        if f.owasp_masvs_category:
            props["owaspCategory"] = f.owasp_masvs_category
        if f.cwe_id:
            props["cweId"] = f.cwe_id
        if props:
            result["properties"] = props

        run["results"].append(result)

    run["tool"]["driver"]["rules"] = list(rules_map.values())

    # Add CWE taxonomy if any findings reference CWEs
    if cwe_ids_seen:
        taxa = []
        for cwe_id in sorted(cwe_ids_seen):
            cwe_num = cwe_id.replace("CWE-", "")
            taxa.append({
                "id": cwe_id,
                "guid": f"cwe-{cwe_num}",
                "shortDescription": {"text": cwe_id},
            })
        run["taxonomies"] = [
            {
                "name": "CWE",
                "version": "4.13",
                "informationUri": "https://cwe.mitre.org/",
                "taxa": taxa,
            }
        ]

    filename = (
        f"{_sanitize_filename(app.package_name)}_findings.sarif"
        if app else "all_findings.sarif"
    )
    content = json.dumps(sarif, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ===========================================================================
# HTML export — Phase 3A: accordion redesign
# ===========================================================================

def _export_findings_html(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as a styled HTML document with accordions."""
    from html import escape

    app_name = escape(app.app_name or app.package_name) if app else "All Applications"
    title = f"Security Findings - {app_name}"

    # Serialize all findings to dicts
    serialized = [_serialize_finding(f) for f in findings]

    # Severity summary counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in serialized:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    # Summary cards
    summary_cards = ""
    for sev_name in SEVERITY_LEVELS:
        color = SEVERITY_COLORS[sev_name]
        bg = SEVERITY_BG_COLORS[sev_name]
        summary_cards += (
            f'<div class="summary-card" style="background:{bg};">'
            f'<div class="count" style="color:{color};">{counts[sev_name]}</div>'
            f'<div class="label" style="color:{color};">{sev_name.title()}</div></div>'
        )

    # Group findings by severity with section headers + accordions
    findings_html = ""
    idx = 1
    for sev_name in SEVERITY_LEVELS:
        sev_findings = [f for f in serialized if f.get("severity") == sev_name]
        if not sev_findings:
            continue
        color = SEVERITY_COLORS[sev_name]
        findings_html += (
            f'<h3 style="color:{color};margin-top:24px;margin-bottom:8px;'
            f'border-bottom:2px solid {color};padding-bottom:4px;">'
            f'{escape(sev_name.upper())} ({len(sev_findings)})</h3>'
        )
        for f in sev_findings:
            findings_html += _build_finding_accordion_html(f, idx)
            idx += 1

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(title)}</title>
{_GOOGLE_FONTS_LINK}
<style>
body {{ font-family: {_FONT_BODY}; margin: 0; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; font-weight: 700; }}
h2 {{ color: #374151; margin-top: 32px; font-weight: 700; }}
h3 {{ font-weight: 700; }}
.summary-grid {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
.summary-card {{ flex: 1; min-width: 100px; padding: 16px; border-radius: 8px; text-align: center; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }}
</style>
{_accordion_js_css()}
</head>
<body>
<h1>{escape(title)}</h1>
<p style="color:#6b7280;">Exported: {datetime.utcnow().isoformat()}</p>

<h2>Summary</h2>
<div class="summary-grid">
{summary_cards}
</div>
<p><strong>Total findings:</strong> {len(findings)}</p>

<h2>Findings</h2>
<div class="no-print" style="margin-bottom:12px;">
<button onclick="expandAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;margin-right:4px;">Expand All</button>
<button onclick="collapseAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;">Collapse All</button>
</div>
{findings_html}

<hr style="margin-top:40px;">
<p style="color:#9ca3af;font-size:12px;text-align:center;">Generated by Mobilicustos Security Assessment Platform</p>
</body>
</html>"""

    filename = (
        f"{_sanitize_filename(app.package_name)}_findings.html"
        if app else "all_findings.html"
    )
    return StreamingResponse(
        io.BytesIO(html_content.encode()),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ===========================================================================
# PDF export — Phase 4A: full field expansion
# ===========================================================================

def _export_findings_pdf(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as a PDF document with all fields."""
    from fpdf import FPDF

    app_name = (app.app_name or app.package_name) if app else "All Applications"

    # Serialize all findings to dicts
    serialized = [_serialize_finding(f) for f in findings]

    class FindingsPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, "Mobilicustos Security Findings", align="R")
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = FindingsPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 14, f"Security Findings - {_pdf_safe_text(app_name)}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 8, f"Exported: {datetime.utcnow().isoformat()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in serialized:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(31, 41, 55)
    pdf.cell(0, 8, f"Total Findings: {len(serialized)}", new_x="LMARGIN", new_y="NEXT")
    for sev_name in SEVERITY_LEVELS:
        r, g, b = SEVERITY_COLORS_RGB[sev_name]
        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 7, f"  {sev_name.upper()}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(counts.get(sev_name, 0)), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(31, 41, 55)
    pdf.ln(6)

    # Findings
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    for i, f in enumerate(serialized, 1):
        _render_finding_to_pdf(pdf, f, i)

    pdf_bytes = pdf.output()
    filename = (
        f"{_sanitize_filename(app.package_name)}_findings.pdf"
        if app else "all_findings.pdf"
    )
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "note")


# ===========================================================================
# Full report endpoint — Phase 1B + 2C: severity sorting + full fields
# ===========================================================================

@router.get("/report/{app_id}")
async def export_full_report(
    app_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export a full security assessment report."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get scans
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.app_id == app_id)
        .order_by(Scan.created_at.desc())
    )
    scans = scans_result.scalars().all()

    # Get findings — Phase 1B: severity ordered
    findings_result = await db.execute(
        _apply_severity_order(select(Finding).where(Finding.app_id == app_id))
    )
    findings = findings_result.scalars().all()

    # Build report — Phase 2C: full field serialization
    report = {
        "title": f"Security Assessment Report - {app.app_name or app.package_name}",
        "generated_at": datetime.utcnow().isoformat(),
        "app": {
            "app_id": app.app_id,
            "package_name": app.package_name,
            "app_name": app.app_name,
            "platform": app.platform,
            "version": app.version_name,
            "framework": app.framework,
            "file_hash": app.file_hash_sha256,
        },
        "executive_summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "scans": [
            {
                "scan_id": str(s.scan_id),
                "scan_type": s.scan_type,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ],
        "findings": [_serialize_finding(f) for f in findings],
    }

    if format == "json":
        content = json.dumps(report, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{_sanitize_filename(app.package_name)}_report.json"'
            },
        )
    elif format == "html":
        html_content = _render_html_report(report)
        return StreamingResponse(
            io.BytesIO(html_content.encode()),
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="{_sanitize_filename(app.package_name)}_report.html"'
            },
        )
    elif format == "pdf":
        pdf_bytes = _generate_pdf(report)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{_sanitize_filename(app.package_name)}_report.pdf"'
            },
        )


# ===========================================================================
# Full report HTML — Phase 3B: accordion redesign
# ===========================================================================

def _render_html_report(report: dict) -> str:
    """Render a security assessment report as HTML with accordions."""
    from html import escape

    summary = report["executive_summary"]
    app_info = report["app"]

    # Sort findings by severity
    sorted_findings = sorted(report["findings"], key=_severity_sort_key)

    # Summary cards
    summary_cards = ""
    for sev_name in SEVERITY_LEVELS:
        color = SEVERITY_COLORS[sev_name]
        bg = SEVERITY_BG_COLORS[sev_name]
        summary_cards += (
            f'<div class="summary-card" style="background:{bg};">'
            f'<div class="count" style="color:{color};">{summary.get(sev_name, 0)}</div>'
            f'<div class="label" style="color:{color};">{sev_name.title()}</div></div>'
        )

    # Group findings by severity with section headers + accordions
    findings_html = ""
    idx = 1
    for sev_name in SEVERITY_LEVELS:
        sev_findings = [f for f in sorted_findings if f.get("severity") == sev_name]
        if not sev_findings:
            continue
        color = SEVERITY_COLORS[sev_name]
        findings_html += (
            f'<h3 style="color:{color};margin-top:24px;margin-bottom:8px;'
            f'border-bottom:2px solid {color};padding-bottom:4px;">'
            f'{escape(sev_name.upper())} ({len(sev_findings)})</h3>'
        )
        for f in sev_findings:
            findings_html += _build_finding_accordion_html(f, idx)
            idx += 1

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(report['title'])}</title>
{_GOOGLE_FONTS_LINK}
<style>
body {{ font-family: {_FONT_BODY}; margin: 0; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; font-weight: 700; }}
h2 {{ color: #374151; margin-top: 32px; font-weight: 700; }}
h3 {{ font-weight: 700; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #f9fafb; font-weight: 600; }}
.summary-grid {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
.summary-card {{ flex: 1; min-width: 100px; padding: 16px; border-radius: 8px; text-align: center; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }}
</style>
{_accordion_js_css()}
</head>
<body>
<h1>{escape(report['title'])}</h1>
<p style="color:#6b7280;">Generated: {escape(report['generated_at'])}</p>

<h2>Application Information</h2>
<table>
<tr><td><strong>Package</strong></td><td>{escape(app_info.get('package_name', ''))}</td></tr>
<tr><td><strong>Name</strong></td><td>{escape(app_info.get('app_name', '') or '')}</td></tr>
<tr><td><strong>Platform</strong></td><td>{escape(app_info.get('platform', ''))}</td></tr>
<tr><td><strong>Version</strong></td><td>{escape(app_info.get('version', '') or '')}</td></tr>
<tr><td><strong>Framework</strong></td><td>{escape(app_info.get('framework', '') or '')}</td></tr>
<tr><td><strong>SHA-256</strong></td><td style="font-family:'Source Code Pro',monospace;font-size:13px;">{escape(app_info.get('file_hash', '') or '')}</td></tr>
</table>

<h2>Executive Summary</h2>
<div class="summary-grid">
{summary_cards}
</div>
<p><strong>Total findings:</strong> {summary['total_findings']}</p>

<h2>Findings</h2>
<div class="no-print" style="margin-bottom:12px;">
<button onclick="expandAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;margin-right:4px;">Expand All</button>
<button onclick="collapseAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;">Collapse All</button>
</div>
{findings_html}

<hr style="margin-top:40px;">
<p style="color:#9ca3af;font-size:12px;text-align:center;">Generated by Mobilicustos Security Assessment Platform</p>
</body>
</html>"""


# ===========================================================================
# Full report PDF — Phase 4B: full field expansion
# ===========================================================================

def _generate_pdf(report: dict) -> bytes:
    """Generate a PDF security assessment report with all fields."""
    from fpdf import FPDF

    class ReportPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, "Mobilicustos Security Assessment", align="R")
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 14, report["title"], new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 8, f"Generated: {report['generated_at']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # App Information
    app_info = report["app"]
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Application Information", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(31, 41, 55)
    for label, key in [
        ("Package", "package_name"), ("Name", "app_name"), ("Platform", "platform"),
        ("Version", "version"), ("Framework", "framework"), ("SHA-256", "file_hash"),
    ]:
        val = app_info.get(key, "") or ""
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(35, 7, f"{label}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(val), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Executive Summary
    summary = report["executive_summary"]
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(31, 41, 55)
    pdf.cell(0, 8, f"Total Findings: {summary['total_findings']}", new_x="LMARGIN", new_y="NEXT")
    for sev_name in SEVERITY_LEVELS:
        r, g, b = SEVERITY_COLORS_RGB[sev_name]
        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 7, f"  {sev_name.upper()}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(summary.get(sev_name, 0)), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(31, 41, 55)
    pdf.ln(6)

    # Findings
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    # Sort findings by severity
    sorted_findings = sorted(report["findings"], key=_severity_sort_key)

    for i, f in enumerate(sorted_findings, 1):
        _render_finding_to_pdf(pdf, f, i)

    return pdf.output()
