"""Generation of self-contained HTML reports for exhaustive-mode summaries."""

import html
import json
import os
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from src.results import AnalysisAggregate, StrategyResult
from src.strategies import STRATEGIES


def _escape(value):
    return html.escape(str(value), quote=True)


def _render_strategy(result: StrategyResult) -> str:
    label = STRATEGIES[result.strategy]
    status = _escape(result.status)
    findings_html = "".join(
        _render_finding(finding) for finding in result.findings
    )
    diagnostics_html = "".join(
        "<li>"
        f"<code>{_escape(diagnostic.code)}</code>: "
        f"{_escape(diagnostic.message)}"
        + (
            f" ({_escape(diagnostic.file)}"
            + (
                f":{diagnostic.line}"
                if diagnostic.line is not None
                else ""
            )
            + ")"
            if diagnostic.file
            else ""
        )
        + "</li>"
        for diagnostic in result.diagnostics
    )
    details = []
    if result.findings:
        details.append(
            "<h4>Constats</h4><ul>"
            f"{findings_html}</ul>"
        )
    if result.diagnostics:
        details.append(
            "<h4>Diagnostics</h4><ul>"
            f"{diagnostics_html}</ul>"
        )
    if not details:
        details.append("<p>Aucun constat pour cette stratégie.</p>")

    return (
        f'<section class="strategy"><h3>{_escape(label)}</h3>'
        f'<p class="status {status}">{status}</p>'
        f'{"".join(details)}'
        "</section>"
    )


def _render_finding(finding) -> str:
    location = finding.location
    if location:
        location_text = location.file
        if location.start_line is not None:
            location_text += f":{location.start_line}"
            if (
                location.end_line is not None
                and location.end_line != location.start_line
            ):
                location_text += f"-{location.end_line}"
    else:
        location_text = "Emplacement inconnu"

    evidence = json.dumps(
        asdict(finding.evidence),
        ensure_ascii=False,
        indent=2,
    )
    confidence = (
        "non estimée"
        if finding.confidence is None
        else f"{finding.confidence:.0%}"
    )
    return (
        "<li class=\"finding\">"
        f"<strong>{_escape(finding.message)}</strong> "
        f"<code>{_escape(finding.rule_id)}</code>"
        f"<p>{_escape(location_text)} · "
        f"{_escape(finding.category)} · "
        f"{_escape(finding.severity)} · "
        f"confiance {confidence} · "
        f"{_escape(finding.kind)}</p>"
        f"<details><summary>Preuve</summary><pre>{_escape(evidence)}</pre></details>"
        "</li>"
    )


def _sanitize_target(target):
    name = Path(os.path.normpath(target)).name or "cible"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-_")
    return safe or "cible"


def generate_report(
    target,
    files,
    aggregate: AnalysisAggregate,
    reports_dir="reports",
):
    """Write an offline report containing raw strategy results and aggregate."""
    generated_at = datetime.now().astimezone()
    report_path = Path(reports_dir) / (
        f"{_sanitize_target(target)}-{generated_at:%Y%m%d-%H%M%S-%f}.html"
    )

    unknown = sorted(
        {result.strategy for result in aggregate.results} - set(STRATEGIES)
    )
    if unknown:
        raise ValueError("Stratégie(s) inconnue(s) : " + ", ".join(unknown))

    strategies_html = "".join(
        _render_strategy(result) for result in aggregate.results
    )
    file_list = "".join(f"<li>{_escape(file)}</li>" for file in files)

    report = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport SASToy — {_escape(target)}</title>
<style>
:root{{color-scheme:dark;--bg:#101820;--panel:#192832;--line:#30434d;--text:#e7f0f3;--muted:#9bb0ba;--cyan:#34d5d0;--yellow:#f4c95d}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "Segoe UI",Arial,sans-serif}}
main{{max-width:1180px;margin:auto;padding:36px 22px}}header{{padding:30px;background:linear-gradient(120deg,#1b3440,#192832);border:1px solid var(--line);border-radius:16px}}
.eyebrow,.muted{{color:var(--muted)}}h1{{margin:.15em 0;color:var(--cyan);font-size:clamp(1.8rem,4vw,2.7rem)}}h2{{margin:0 0 16px}}h3{{margin:0 0 8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:18px 0}}.card,.section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}}
.value{{font-size:1.15rem;font-weight:650;overflow-wrap:anywhere}}.badge,.status{{display:inline-block;border-radius:20px;padding:4px 10px;font-weight:700;font-size:.85rem}}
.badge,.partial,.unavailable{{color:var(--yellow);background:#493f20}}.completed{{color:#9ce6b0;background:#20452c}}.failed{{color:#ffaaaa;background:#482a30}}.section{{margin-top:18px}}.strategy{{padding:18px 0;border-bottom:1px solid var(--line)}}.strategy:last-child{{border-bottom:0}}.finding{{margin:12px 0}}.finding p{{color:var(--muted)}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101820;padding:12px;border-radius:8px}}
footer{{padding:24px;color:var(--muted);text-align:center}}@media(max-width:600px){{main{{padding:16px 12px}}header,.card,.section{{padding:16px}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">SASTOY · RAPPORT EXHAUSTIF</div>
<h1>Résultats des stratégies</h1>
<p><span class="badge">AGRÉGAT BRUT · SANS SYNTHÈSE NI SCORING</span></p>
<p>Les résultats ci-dessous proviennent des stratégies exécutées.</p>
</header>
<div class="grid">
<div class="card"><div class="muted">Cible</div><div class="value">{_escape(target)}</div></div>
<div class="card"><div class="muted">Date</div><div class="value">{generated_at:%Y-%m-%d %H:%M:%S %Z}</div></div>
<div class="card"><div class="muted">Statut agrégé</div><div class="value">{_escape(aggregate.status)}</div></div>
<div class="card"><div class="muted">Stratégies exécutées</div><div class="value">{len(aggregate.results)}</div></div>
<div class="card"><div class="muted">Constats</div><div class="value">{len(aggregate.findings)}</div></div>
</div>
<section class="section"><h2>Fichiers ciblés</h2>
<ul>{file_list or "<li>Aucun fichier Python sélectionné.</li>"}</ul></section>
<section class="section"><h2>Résultats par stratégie</h2>
{strategies_html or "<p>Aucune stratégie sélectionnée.</p>"}
</section>
<footer>Rapport autonome hors ligne · Généré par SASToy</footer>
</main></body></html>"""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    return report_path.resolve()
