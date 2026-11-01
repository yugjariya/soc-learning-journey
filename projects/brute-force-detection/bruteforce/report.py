"""Self-contained HTML, JSON and Markdown reports; no external assets or services."""
import html
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path


TITLES = {"brute_force": "Repeated password failures", "password_spray": "Password-spray pattern",
          "distributed_attack": "Distributed login attempts", "suspicious_success": "Success after failure burst"}


def esc(value):
    return html.escape(str(value), quote=True)


def markdown(value):
    return str(value).replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def write_reports(report, events, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "alerts.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    normalized = []
    for event in events:
        record = asdict(event)
        record["timestamp"] = event.timestamp.isoformat()
        normalized.append(json.dumps(record, ensure_ascii=True))
    (output / "events.jsonl").write_text("\n".join(normalized) + ("\n" if normalized else ""), encoding="utf-8")
    (output / "investigation.md").write_text(render_markdown(report), encoding="utf-8")
    (output / "dashboard.html").write_text(render_html(report, events), encoding="utf-8")


def render_markdown(report):
    summary, source = report["summary"], report["source"]
    rows = [f"# {markdown(report['label'])}", "", "## Scope and evidence", "",
            f"Source: `{markdown(source['name'])}` · SHA-256: `{source['sha256']}`", "",
            f"Analyzed {summary['parsed_events']} authentication events: {summary['failures']} failures and {summary['successes']} successes. "
            f"Skipped {summary['skipped_lines']} unrelated lines; {summary['malformed_lines']} authentication lines could not be parsed.", "",
            "Counts describe all parsed input, including allowlisted sources. Alert rules exclude allowlisted sources.", "",
            f"Event range (UTC): {summary['first_event']} to {summary['last_event']}", "",
            "## Findings", ""]
    if not report["alerts"]:
        rows.append("No configured thresholds were met. This does not establish absence of an attack.")
    for alert in report["alerts"]:
        rows.extend([f"### {markdown(alert['id'])}: {TITLES.get(alert['type'], markdown(alert['type']))}", "",
                     f"**Severity:** {markdown(alert['severity'])} · **Host:** `{markdown(alert['host'])}` · **ATT&CK:** {markdown(alert['mitre_technique'])}", "",
                     markdown(alert["description"]), "",
                     f"- UTC interval: {alert['first_seen']} — {alert['last_seen']}",
                     f"- Source addresses: {', '.join(markdown(s) for s in alert['source_ips'])}",
                     f"- Accounts: {', '.join(markdown(s) for s in alert['usernames'])}",
                     f"- Distinct failure records in evidence: {alert['failure_count']}",
                     f"- Original log line numbers: {', '.join(map(str, alert['evidence_lines']))}", ""])
    rows.extend(["## Assessment and response", "",
                 "These are behavioral detections. A successful login after failures requires investigation; it does not prove account compromise. "
                 "Authentication logs do not reveal whether the same password was tried against multiple accounts. Multiple sources do not establish common ownership.", "",
                 "1. Preserve original logs and hash; confirm clock offsets, parser coverage, and asset ownership.",
                 "2. Compare accounts and source addresses with approved activity, NAT/VPN egress, and scheduled automation.",
                 "3. Review successful login method, session activity, process execution, and account-owner confirmation.",
                 "4. If unauthorized activity is confirmed, follow the response policy: restrict abusive sources, revoke affected sessions, and rotate affected credentials or keys.",
                 "5. Reduce exposure with MFA where supported, key-based SSH, access restrictions, rate limits, and monitoring. Validate changes before rollout.", "",
                 "No containment action was executed by this analyzer. See `docs/PLAYBOOK.md` for investigation steps.", "",
                 "## Detection configuration", "", "```json", json.dumps(report["config"], indent=2), "```", "",
                 "Yearless syslog assumes the configured year and fixed UTC offset. Split files across year boundaries before analysis. "
                 "Duplicate source records are counted separately; deduplicate upstream. Batch analysis holds parsed events in memory.", ""])
    return "\n".join(rows)


def render_html(report, events):
    s = report["summary"]
    buckets = Counter(e.timestamp.strftime("%Y-%m-%d %H:%M") for e in events if e.outcome == "failure")
    # The chart stays bounded for large inputs; the complete timeline remains in events.jsonl.
    bucket_items = list(sorted(buckets.items()))[:48]
    maximum = max(buckets.values(), default=1)
    bars = "".join(f'<div class="bar-column" title="{esc(t)} UTC"><span>{count}</span><div class="bar" style="height:{max(3, count / maximum * 120):.1f}px"></div><small>{esc(t[11:])}<br>{esc(t[5:10])}</small></div>' for t, count in bucket_items)
    alert_html = []
    for alert in report["alerts"]:
        alert_html.append(f'''<article class="alert" data-severity="{esc(alert['severity'])}">
          <div class="alert-head"><span class="badge {esc(alert['severity'])}">{esc(alert['severity'])}</span><span class="mono muted">{esc(alert['id'])}</span><span class="technique">{esc(alert['mitre_technique'])}</span></div>
          <h3>{esc(TITLES.get(alert['type'], alert['type']))}</h3><p class="description">{esc(alert['description'])}</p>
          <dl><div><dt>SOURCE</dt><dd class="mono">{esc(', '.join(alert['source_ips']))}</dd></div><div><dt>ACCOUNT / HOST</dt><dd>{esc(', '.join(alert['usernames']))} <span class="muted">on {esc(alert['host'])}</span></dd></div></dl>
          <div class="alert-foot"><span>{alert['failure_count']} failure records</span><span>{esc(alert['first_seen'][11:19])} → {esc(alert['last_seen'][11:19])} UTC</span></div>
          <details><summary>Inspect evidence</summary><p>Original log lines: <span class="mono">{esc(', '.join(map(str, alert['evidence_lines'])))}</span></p><p>Full interval: {esc(alert['first_seen'])} to {esc(alert['last_seen'])}</p></details></article>''')
    status = "Review required" if report["alerts"] else "No thresholds met"
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel / Authentication investigation</title><style>
:root{color-scheme:dark;--bg:#0a101b;--panel:#111a29;--line:#263246;--text:#e8eef7;--muted:#94a7bf;--mint:#6ae3c0;--orange:#ffbd75;--red:#ff7e8f}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1160px;margin:auto;padding:0 32px 56px}header{height:85px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{font-weight:750;letter-spacing:3px;font-size:17px}.brand b{color:var(--mint)}.muted,small{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.eyebrow{color:var(--mint);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-top:36px}.intro{display:flex;justify-content:space-between;align-items:center;gap:24px}.intro h1{font-size:38px;line-height:1.2;letter-spacing:-1.2px;margin:12px 0}.intro p{color:var(--muted);margin:0 0 25px;max-width:760px}.status{border:1px solid #714c39;color:var(--orange);padding:8px 14px;border-radius:50px;white-space:nowrap;font-size:12px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:5px 0 25px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}.stat small{font-size:11px;letter-spacing:1.5px}.stat strong{display:block;font-size:34px;font-weight:600;margin-top:5px}.stat.alert-stat strong{color:var(--red)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:23px;margin:22px 0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px}h2{font-size:18px;margin:0}h3{font-size:19px;margin:15px 0 6px}.chart{height:185px;display:flex;align-items:flex-end;gap:16px;overflow-x:auto;padding-top:15px}.bar-column{min-width:38px;flex:1;text-align:center;display:flex;flex-direction:column;justify-content:flex-end;font-size:11px;color:var(--muted)}.bar{background:linear-gradient(0deg,#286f74,var(--mint));border-radius:5px 5px 0 0;margin:5px 0 9px;min-width:12px}.filters{display:flex;gap:7px}button{background:transparent;border:1px solid var(--line);color:var(--muted);padding:7px 12px;border-radius:6px;cursor:pointer}button.active,button:focus-visible{color:var(--mint);border-color:var(--mint)}.alerts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}.alert{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:22px;min-width:0}.alert[hidden]{display:none}.alert-head{display:flex;align-items:center;gap:10px;font-size:11px}.badge{text-transform:uppercase;letter-spacing:1px;padding:3px 8px;border-radius:5px}.high{background:#352b20;color:var(--orange)}.critical{background:#3b202c;color:var(--red)}.technique{margin-left:auto;color:var(--muted)}.description{font-size:13px;color:var(--muted)}dl{display:grid;gap:14px;margin:20px 0}dt{font-size:10px;letter-spacing:1.2px;color:var(--muted)}dd{margin:3px 0 0;font-size:12px;overflow-wrap:anywhere}.alert-foot{display:flex;justify-content:space-between;flex-wrap:wrap;font-size:11px;border-top:1px solid var(--line);padding-top:13px;color:var(--muted)}details{font-size:12px;margin-top:15px}summary{color:var(--mint);cursor:pointer}details p{overflow-wrap:anywhere}.response{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:18px}.response b{font-size:13px}.response p{font-size:12px;color:var(--muted);margin:5px 0}.note{font-size:12px;color:var(--muted);line-height:1.7}footer{border-top:1px solid var(--line);margin-top:27px;padding-top:18px;font-size:11px;color:var(--muted);overflow-wrap:anywhere}@media(max-width:700px){main{padding:0 16px 32px}.intro{display:block}.intro h1{font-size:29px}.status{display:inline-block;margin-bottom:20px}.stats{grid-template-columns:1fr 1fr}.alerts,.response{grid-template-columns:1fr}.section-head{align-items:flex-start;flex-direction:column}.chart{gap:8px}.brand{font-size:14px}header{height:65px}.stat{padding:15px}}
</style></head><body><main>''' + f'''
<header><div class="brand"><b>◈</b> SENTINEL <span class="muted">/ LAB</span></div><span class="mono muted">SSH · AUTHENTICATION</span></header>
<div class="eyebrow">Detection & investigation / offline analysis</div>
<div class="intro"><div><h1>{esc(report['label'])}</h1><p>Authentication evidence, correlated into reviewable findings. Source: <span class="mono">{esc(report['source']['name'])}</span></p></div><span class="status">● {status}</span></div>
<div class="stats"><div class="stat"><small>AUTH EVENTS</small><strong>{s['parsed_events']}</strong></div><div class="stat"><small>FAILED LOGINS</small><strong>{s['failures']}</strong></div><div class="stat"><small>SOURCE ADDRESSES</small><strong>{s['unique_sources']}</strong></div><div class="stat alert-stat"><small>FINDINGS</small><strong>{s['alerts']}</strong></div></div>
<section class="panel"><div class="section-head"><h2>Failure activity</h2><span class="mono muted">UTC · failures per minute</span></div><div class="chart">{bars or '<p class="muted">No failure events in input.</p>'}</div></section>
<div class="section-head"><h2>Investigation queue</h2><div class="filters" aria-label="Filter findings"><button type="button" class="active" aria-pressed="true" data-filter="all">All findings</button><button type="button" aria-pressed="false" data-filter="critical">Critical</button><button type="button" aria-pressed="false" data-filter="high">High</button></div></div>
<div class="alerts">{''.join(alert_html) or '<p class="muted">No configured detection threshold was met.</p>'}</div><p id="filter-empty" class="muted" hidden>No findings match this filter.</p>
<section class="panel"><h2>Recommended investigation</h2><div class="response"><div><b>01 / Preserve & validate</b><p>Retain original logs, verify timestamps, review parser gaps, and compare with approved account activity.</p></div><div><b>02 / Correlate sessions</b><p>Review successful authentication methods, session commands, endpoint telemetry, and account ownership.</p></div><div><b>03 / Contain if confirmed</b><p>Follow incident policy to restrict sources, revoke sessions, and rotate affected credentials or keys.</p></div></div></section>
<p class="note">{s['successes']} successful logins · {s['skipped_lines']} unrelated lines skipped · {s['malformed_lines']} malformed authentication lines. Event range: {esc(s['first_event'])} to {esc(s['last_event'])}. Summary counts include allowlisted sources; findings exclude them. Chart shows the first 48 occupied UTC minute buckets; dates are shown as MM-DD.</p>
<p class="note">Behavioral detections require analyst validation. A successful login after failures does not prove compromise, and multi-account failures do not prove password reuse. No blocking or other containment was performed. Open investigation.md for the response notes and alerts.json for configuration.</p>
<footer>Evidence SHA-256 · <span class="mono">{esc(report['source']['sha256'])}</span><br>Generated {esc(report['generated_at'])} · Built with Python standard library · Synthetic lab when indicated in title</footer>
<script>document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{{document.querySelectorAll('[data-filter]').forEach(b=>{{b.classList.toggle('active',b===button);b.setAttribute('aria-pressed',String(b===button));}});let visible=0;document.querySelectorAll('[data-severity]').forEach(card=>{{card.hidden=button.dataset.filter!=='all'&&card.dataset.severity!==button.dataset.filter;if(!card.hidden)visible++;}});document.getElementById('filter-empty').hidden=visible>0;}}));</script>
</main></body></html>'''
