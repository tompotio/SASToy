"""Generation of self-contained HTML reports for exhaustive-mode prototypes."""

import html
import json
import os
import re
from datetime import datetime
from pathlib import Path

from src.exhaustive import STRATEGY_LABELS, UNAVAILABLE_STRATEGIES, StrategyResult


DEMO_RECOMMENDATIONS = [
    "Examiner les valeurs de toute entrée externe avant leur utilisation.",
    "Préférer des API de traitement sûres et limiter les privilèges du processus.",
]


def _escape(value):
    return html.escape(str(value), quote=True)


def _render_strategy_result(result):
    label = STRATEGY_LABELS.get(result.strategy, result.strategy)
    body = [f'<section class="strategy"><h3>{_escape(label)}</h3>']
    if result.status == "error":
        body.append(
            '<p class="status error">Échec de la stratégie de démonstration</p>'
            f"<p>{_escape(result.error)}</p></section>"
        )
        return "".join(body)

    body.append(
        '<p class="status demo">Exemple fictif — aucune analyse réelle exécutée</p>'
    )
    if not isinstance(result.output, list) or not result.output:
        body.append("<p>Aucun exemple fourni.</p></section>")
        return "".join(body)

    body.append(
        "<div class=\"table-wrap\"><table><thead><tr>"
        "<th>Fichier d'exemple</th><th>Règle</th><th>Ligne</th>"
        "<th>Description</th><th>Éléments de preuve</th>"
        "</tr></thead><tbody>"
    )
    for item in result.output:
        if not isinstance(item, dict):
            continue
        body.append(
            "<tr>"
            f"<td>{_escape(item.get('file', '—'))}</td>"
            f"<td><code>{_escape(item.get('rule', '—'))}</code></td>"
            f"<td>{_escape(item.get('line', '—'))}</td>"
            f"<td>{_escape(item.get('description', '—'))}</td>"
            f"<td>{_escape(item.get('evidence', '—'))}</td>"
            "</tr>"
        )
    body.append("</tbody></table></div></section>")
    return "".join(body)


def _render_chart(results):
    counts = [
        (STRATEGY_LABELS.get(result.strategy, result.strategy), len(result.output))
        for result in results
        if result.status == "demo" and isinstance(result.output, list)
    ]
    max_count = max((count for _, count in counts), default=1)
    bars = []
    for label, count in counts:
        width = max(4, round(count / max_count * 100))
        bars.append(
            '<div class="bar-row">'
            f'<span>{_escape(label)}</span>'
            f'<div class="bar-track"><div class="bar" style="width:{width}%"></div></div>'
            f"<strong>{count}</strong></div>"
        )
    return (
        '<div class="chart" role="img" aria-label="Comptages fictifs par stratégie">'
        + ("".join(bars) or "<p>Aucune stratégie sélectionnée.</p>")
        + "</div>"
    )


def _sanitize_target(target):
    name = Path(os.path.normpath(target)).name or "cible"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-_")
    return safe or "cible"


def generate_report(
    target,
    files,
    results,
    duration_seconds,
    ai_status,
    ai_recommendations=None,
    reports_dir="reports",
):
    """Write an offline HTML demo report and return its absolute path."""
    generated_at = datetime.now().astimezone()
    report_path = Path(reports_dir) / (
        f"{_sanitize_target(target)}-{generated_at:%Y%m%d-%H%M%S-%f}.html"
    )

    strategies_html = "".join(_render_strategy_result(result) for result in results)
    unavailable_html = "".join(
        f'<li><strong>{_escape(label)}</strong> : non implémentée, non exécutée.</li>'
        for label in UNAVAILABLE_STRATEGIES.values()
    )
    file_list = "".join(f"<li>{_escape(file)}</li>" for file in files)
    general_recommendations = "".join(
        f"<li>{_escape(recommendation)}</li>"
        for recommendation in DEMO_RECOMMENDATIONS
    )
    if ai_recommendations:
        ai_body = f"<p>{_escape(ai_recommendations)}</p>"
    else:
        ai_body = f"<p>{_escape(ai_status)}</p>"

    report = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport SASToy — {_escape(target)}</title>
<style>
:root{{color-scheme:dark;--bg:#101820;--panel:#192832;--line:#30434d;--text:#e7f0f3;--muted:#9bb0ba;--cyan:#34d5d0;--yellow:#f4c95d;--red:#ff7474}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "Segoe UI",Arial,sans-serif}}
main{{max-width:1180px;margin:auto;padding:36px 22px}}header{{padding:30px;background:linear-gradient(120deg,#1b3440,#192832);border:1px solid var(--line);border-radius:16px}}
.eyebrow,.muted{{color:var(--muted)}}h1{{margin:.15em 0;color:var(--cyan);font-size:clamp(1.8rem,4vw,2.7rem)}}h2{{margin:0 0 16px}}h3{{margin:0 0 8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:18px 0}}.card,.section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}}
.value{{font-size:1.15rem;font-weight:650;overflow-wrap:anywhere}}.badge,.status{{display:inline-block;border-radius:20px;padding:4px 10px;font-weight:700;font-size:.85rem}}
.badge,.demo{{color:var(--yellow);background:#493f20}}.error{{color:var(--red);background:#482a30}}.section{{margin-top:18px}}.strategy{{padding:18px 0;border-bottom:1px solid var(--line)}}.strategy:last-child{{border-bottom:0}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;min-width:760px}}th,td{{padding:11px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}th{{color:var(--cyan)}}code{{color:var(--cyan)}}
.bar-row{{display:grid;grid-template-columns:minmax(130px,220px) 1fr 30px;gap:12px;align-items:center;margin:10px 0}}.bar-track{{height:12px;background:#293b44;border-radius:8px;overflow:hidden}}.bar{{height:100%;background:var(--cyan);border-radius:8px}}
footer{{padding:24px;color:var(--muted);text-align:center}}@media(max-width:600px){{main{{padding:16px 12px}}header,.card,.section{{padding:16px}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">SASTOY · RAPPORT DE DÉMONSTRATION</div>
<h1>Analyse exhaustive — prototype</h1>
<p><span class="badge">DONNÉES FICTIVES · AUCUN SCAN RÉEL</span></p>
<p>Les exemples, comptages et recommandations ci-dessous sont statiques.
Ils ne décrivent pas la cible et ne valident aucune règle de gravité ou d'agrégation.</p>
</header>
<div class="grid">
<div class="card"><div class="muted">Cible</div><div class="value">{_escape(target)}</div></div>
<div class="card"><div class="muted">Date</div><div class="value">{generated_at:%Y-%m-%d %H:%M:%S %Z}</div></div>
<div class="card"><div class="muted">Durée</div><div class="value">{duration_seconds:.2f} s</div></div>
<div class="card"><div class="muted">Statut</div><div class="value">Prototype — données fictives</div></div>
</div>
<section class="section"><h2>Fichiers ciblés (non analysés dans ce prototype)</h2>
<ul>{file_list or "<li>Aucun fichier Python sélectionné.</li>"}</ul></section>
<section class="section"><h2>Vue synthétique provisoire</h2>
<p class="muted">Comptages statiques d'exemples, sans agrégation ni gravité.</p>
{_render_chart(results)}</section>
<section class="section"><h2>Sorties des stratégies</h2>
{strategies_html or "<p>Aucune stratégie sélectionnée.</p>"}
<h3>Stratégies indisponibles</h3><ul>{unavailable_html}</ul></section>
<section class="section"><h2>Recommandations générales (exemples fictifs)</h2>
<ul>{general_recommendations}</ul></section>
<section class="section"><h2>Analyse IA — section distincte</h2>
<p>État : {_escape(ai_status)}</p>{ai_body}</section>
<footer>Rapport autonome hors ligne · Généré par SASToy</footer>
</main></body></html>"""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    return report_path.resolve()


def anonymized_ai_summary(results):
    """Build a counts-only prompt context with no file paths or finding values."""
    summary = []
    for result in results:
        if result.status == "demo" and isinstance(result.output, list):
            summary.append(
                {
                    "strategy": result.strategy,
                    "example_count": len(result.output),
                    "data_type": "fictitious",
                }
            )
    return json.dumps(summary, ensure_ascii=True)
