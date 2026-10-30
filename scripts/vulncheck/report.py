"""JSON and Markdown report writers."""

import json
import os

from vulncheck import match

SEVERITY_RANKS = (4, 3, 2, 1, 0)


def write_reports(reports_dir, metadata, summary, findings, resolved, gone):
    """Write scan.json and scan.md; returns the two paths."""
    os.makedirs(reports_dir, exist_ok=True)
    ordered = sorted(findings,
                     key=lambda f: (-f["severity_rank"], f["vuln_id"],
                                    f["asset_key"]))
    doc = {
        "schema": "vulncheck.report/1",
        "metadata": metadata,
        "summary": summary,
        "findings": ordered,
        "resolved": resolved,
        "gone": gone,
    }
    json_path = os.path.join(reports_dir, "scan.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    md_path = os.path.join(reports_dir, "scan.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_render_markdown(metadata, summary, ordered, resolved, gone))
    return json_path, md_path


def build_summary(assets, findings, deltas):
    by_layer = {}
    for asset in assets:
        by_layer[asset["layer"]] = by_layer.get(asset["layer"], 0) + 1
    by_severity = {}
    for rank in SEVERITY_RANKS:
        by_severity[match.severity_label(rank)] = 0
    for finding in findings:
        label = match.severity_label(finding["severity_rank"])
        by_severity[label] = by_severity.get(label, 0) + 1
    return {
        "assets_total": len(assets),
        "assets_by_layer": by_layer,
        "findings_total": len(findings),
        "by_severity": by_severity,
        "delta": deltas,
    }


def _render_markdown(metadata, summary, findings, resolved, gone):
    lines = []
    md = lines.append
    md("# Vulnerability Scan Report")
    md("")
    md("- Host: %s" % metadata.get("host_id"))
    if metadata.get("os_pretty_name"):
        md("- OS: %s" % metadata["os_pretty_name"])
    md("- Started: %s / Finished: %s (duration %.1fs)"
       % (metadata.get("started"), metadata.get("finished"),
          metadata.get("duration_seconds", 0.0)))
    md("- Layers: %s" % ", ".join(metadata.get("layers") or []))
    md("- Sources: %s" % ", ".join(metadata.get("sources") or []))
    md("- Severity floor: %s" % metadata.get("severity_floor"))
    md("")
    md("## Summary")
    md("")
    md("Scanned %d asset(s): %s" % (
        summary["assets_total"],
        ", ".join("%s=%d" % (k, v)
                  for k, v in sorted(summary["assets_by_layer"].items()))))
    md("")
    md("| Severity | Findings |")
    md("| --- | --- |")
    for rank in SEVERITY_RANKS:
        label = match.severity_label(rank)
        md("| %s | %d |" % (label, summary["by_severity"].get(label, 0)))
    md("")
    md("Total active findings: **%d**" % summary["findings_total"])
    delta = summary.get("delta") or {}
    fdelta = delta.get("findings") or {}
    interesting = {k: v for k, v in fdelta.items()
                   if k in ("new", "reopened", "resolved", "gone") and v}
    if interesting:
        md("")
        md("Changes since last scan: %s" % ", ".join(
            "%s=%d" % (k, v) for k, v in sorted(interesting.items())))
    md("")
    if findings:
        md("## Findings")
        md("")
        current_rank = None
        for finding in findings:
            rank = finding["severity_rank"]
            if rank != current_rank:
                current_rank = rank
                md("### %s" % match.severity_label(rank).title())
                md("")
            md("#### %s — %s" % (finding["vuln_id"], finding["asset_key"]))
            md("")
            bits = ["severity: %s" % match.severity_label(rank)]
            if finding.get("severity_detail"):
                bits.append(finding["severity_detail"])
            md("- %s" % "; ".join(bits))
            md("- Source: %s%s" % (
                finding.get("source", ""),
                (" (also: %s)" % ", ".join(finding["also_reported_by"]))
                if finding.get("also_reported_by") else ""))
            if finding.get("summary"):
                md("- Summary: %s" % finding["summary"].replace("\n", " "))
            if finding.get("url"):
                md("- Record: %s" % finding["url"])
            for ref in (finding.get("references") or [])[:5]:
                md("- Reference: %s" % ref)
            md("")
    else:
        md("## Findings")
        md("")
        md("No active findings at or above the severity floor.")
        md("")
    if resolved or gone:
        md("## Previously reported, now inactive")
        md("")
        for status, items in (("resolved", resolved), ("gone", gone)):
            if items:
                md("- %s: %s" % (status.title(), ", ".join(
                    "%s on %s" % (i["vuln_id"], i["asset_key"])
                    for i in items)))
        md("")
    warnings = metadata.get("warnings") or []
    if warnings:
        md("## Warnings")
        md("")
        for warning in warnings:
            md("- %s" % warning)
        md("")
    return "\n".join(lines)
