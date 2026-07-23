from __future__ import annotations

import base64
import html
from importlib.resources import files
from pathlib import Path
from typing import Any

from guardrails_cli.presentation import severity_detail

from ._atomic import write_text


def export_html(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    write_text(path, to_html(report))
    return path


def to_html(report: dict[str, Any]) -> str:
    summary = dict(report.get("summary") or {})
    metadata = dict(report.get("metadata") or {})
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    counts = _counts(summary, extensions)
    rows = "\n".join(_extension_html(item) for item in sorted(extensions, key=_priority, reverse=True))
    scan_id = metadata.get("scan_id") or report.get("scan_id", "unknown")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <title>Guardrails local extension report</title>
  <style>
    :root {{--bg:#fff;--panel:#f6f8fa;--panel2:#edf2f5;--line:#d9e0e5;--text:#14202b;--muted:#516273;--brand:#c9ff45;--brand-ink:#5d7800;--allow:#1f8a4c;--review:#9a6512;--block:#b4373d;--incomplete:#67519b;}}
    *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,system-ui,sans-serif}} code{{font-family:"Cascadia Code",ui-monospace,monospace}}
    main{{width:min(1180px,calc(100% - 32px));margin:auto;padding:40px 0 80px}} header{{display:flex;justify-content:space-between;gap:24px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:28px}}
    .brand{{display:flex;align-items:center;gap:14px}} .mark{{display:block;width:38px;height:38px;object-fit:contain}}
    h1,h2,p{{margin:0}} h1{{font-size:20px;letter-spacing:.08em;text-transform:uppercase}} .sub{{margin-top:6px;color:var(--muted);font-size:12px}} .identity{{color:var(--muted);font-size:11px;text-align:right}}
    .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin:28px 0;background:var(--line);border:1px solid var(--line)}} .stat{{background:var(--panel);padding:18px}} .stat span{{display:block;color:var(--muted);font-size:10px;text-transform:uppercase}} .stat strong{{display:block;margin-top:9px;font:700 25px ui-monospace,monospace}}
    .extension{{margin-top:14px;border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}} .extension-head{{display:grid;grid-template-columns:1fr auto;gap:16px;padding:20px}} .extension-head code{{display:block;margin-top:5px;color:var(--muted);font-size:11px}} .decision{{height:max-content;border:1px solid currentColor;border-radius:4px;padding:6px 9px;font:800 10px ui-monospace,monospace}} .allow{{color:var(--allow)}} .review{{color:var(--review)}} .block{{color:var(--block)}} .incomplete{{color:var(--incomplete)}}
    .facts{{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--line);border-top:1px solid var(--line)}} .fact{{background:var(--panel2);padding:13px}} .fact span{{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}} .fact strong{{display:block;overflow:hidden;margin-top:6px;font-size:12px;text-overflow:ellipsis}}
    .reason{{padding:18px 20px;border-top:1px solid var(--line);color:#33414d;font-size:13px;line-height:1.55}} table{{width:100%;border-collapse:collapse}} th,td{{border-top:1px solid var(--line);padding:11px 14px;text-align:left;font-size:11px;vertical-align:top}} th{{color:var(--muted);font-size:9px;text-transform:uppercase}} td:last-child{{color:#516273}} footer{{margin-top:30px;color:var(--muted);font-size:10px}}
    @media(max-width:760px){{header{{align-items:start;flex-direction:column}}.identity{{text-align:left}}.stats{{grid-template-columns:repeat(2,1fr)}}.facts{{grid-template-columns:repeat(2,1fr)}}th:nth-child(3),td:nth-child(3){{display:none}}}}
    @media print{{body{{background:white;color:#111}}.extension,.stat,.fact{{background:white}}}}
  </style>
</head>
<body><main>
  <header><div class="brand">{_logo_html()}<div><h1>Guardrails</h1><p class="sub">Local IDE extension report</p></div></div><div class="identity"><code>{_escape(scan_id)}</code><br>{_escape(metadata.get('created_at') or report.get('created_at', ''))}</div></header>
  <section class="stats">{_stat('Extensions',len(extensions))}{_stat('Allow',counts['allow'])}{_stat('Review',counts['review'])}{_stat('Block / incomplete',counts['block'] + counts['incomplete'])}</section>
  {rows or '<p>No extension results were recorded.</p>'}
  <footer>Generated locally by Guardrails. Extension code was not executed by the scanner.</footer>
</main></body></html>"""


def _extension_html(extension: dict[str, Any]) -> str:
    decision = _decision(extension)
    coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    artifact = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    sha = extension.get("artifact_sha256") or artifact.get("sha256") or extension.get("artifact_hash") or "unavailable"
    findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
    finding_rows = "".join(
        f"<tr><td>{_escape(severity_detail(item))}</td><td><code>{_escape(item.get('rule_id',''))}</code></td><td>{_escape(item.get('evidence_class') or 'unknown')}</td><td>{_escape(item.get('evidence_summary',''))}</td></tr>"
        for item in findings[:50]
    ) or '<tr><td colspan="4">No findings reported.</td></tr>'
    reason = extension.get("decision_reason") or extension.get("verdict_reason") or "No explanation was recorded."
    return f"""<article class="extension">
      <div class="extension-head"><div><h2>{_escape(extension.get('name') or extension.get('extension_id') or 'Unknown extension')}</h2><code>{_escape(extension.get('extension_id','unknown'))}@{_escape(extension.get('version','unknown'))}</code></div><span class="decision {decision}">{decision.upper()}</span></div>
      <div class="facts">{_fact('IDE',_ide_label(extension.get('client') or extension.get('source') or 'local'))}{_fact('Coverage',str(int(extension.get('coverage_percent') if extension.get('coverage_percent') is not None else coverage.get('coverage_percent') or 0))+'%')}{_fact('Risk',str(int(extension.get('risk_score') or 0))+'/100')}{_fact('Malware evidence',str(int(extension.get('malware_score') or 0))+'/100')}{_fact('Artifact SHA-256',str(sha)[:18]+'…' if len(str(sha))>18 else sha)}</div>
      <p class="reason">{_escape(reason)}</p>
      <table><thead><tr><th>Severity</th><th>Rule</th><th>Evidence</th><th>Summary</th></tr></thead><tbody>{finding_rows}</tbody></table>
    </article>"""


def _stat(label: str, value: object) -> str:
    return f'<div class="stat"><span>{_escape(label)}</span><strong>{_escape(value)}</strong></div>'


def _fact(label: str, value: object) -> str:
    return f'<div class="fact"><span>{_escape(label)}</span><strong>{_escape(value)}</strong></div>'


def _logo_html() -> str:
    """Embed the exact website PNG so saved reports remain self-contained."""
    payload = files("guardrails_cli").joinpath("assets/guardrails-mark.png").read_bytes()
    encoded = base64.b64encode(payload).decode("ascii")
    return f'<img class="mark" alt="" src="data:image/png;base64,{encoded}">'


def _escape(value: object) -> str:
    return html.escape(str(value))


def _decision(extension: dict[str, Any]) -> str:
    value = str(extension.get("decision") or "").lower()
    if value in {"allow", "review", "block", "incomplete"}:
        return value
    return {"clean": "allow", "review": "review", "suspicious": "review", "malicious": "block"}.get(str(extension.get("verdict") or "").lower(), "incomplete")


def _counts(summary: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, int]:
    recorded = summary.get("decision_counts") if isinstance(summary.get("decision_counts"), dict) else None
    if recorded:
        return {key: int(recorded.get(key) or 0) for key in ("allow", "review", "block", "incomplete")}
    result = {key: 0 for key in ("allow", "review", "block", "incomplete")}
    for extension in extensions:
        result[_decision(extension)] += 1
    return result


def _priority(extension: dict[str, Any]) -> tuple[int, int, int]:
    return ({"allow":1,"review":2,"incomplete":3,"block":4}[_decision(extension)],int(extension.get("malware_score") or 0),int(extension.get("risk_score") or 0))


def _ide_label(value: object) -> str:
    label = str(value)
    return {"vscode": "VS Code", "vscode-insiders": "VS Code Insiders", "cursor": "Cursor", "windsurf": "Windsurf", "vscodium": "VSCodium"}.get(label.lower(), label)
