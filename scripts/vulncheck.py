#!/usr/bin/env python3
"""vulncheck command line interface: scan, inventory, status."""

import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vulncheck import inventory, match, report, sources, state  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALID_LAYERS = ("os", "python", "container")
FLOOR_CHOICES = ("none", "low", "medium", "high", "critical")


class ConfigError(Exception):
    """Fatal configuration problem (exit code 2)."""


def default_config_path():
    return os.path.join(PROJECT_ROOT, "config", "vulncheck.json")


def load_config(path):
    if not os.path.exists(path):
        raise ConfigError("config file not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError("cannot read config %s: %s" % (path, exc))
    if not isinstance(cfg, dict):
        raise ConfigError("config %s must be a JSON object" % path)
    cfg.setdefault("layers", ["os", "python", "container"])
    cfg.setdefault("severity_floor", "none")
    cfg.setdefault("host_id", None)
    if "sources" not in cfg:
        cfg["sources"] = [{"name": "osv", "type": "osv", "enabled": True}]
    cfg.setdefault("output", {})
    cfg["output"].setdefault("reports_dir", "reports")
    cfg["output"].setdefault("state_file", "state/state.json")
    cfg.setdefault("assets_file", "config/assets.json")
    return cfg


def resolve(path):
    if not path or os.path.isabs(path):
        return path
    return os.path.join(PROJECT_ROOT, path)


def parse_layers(raw):
    layers = [part.strip() for part in raw.split(",") if part.strip()]
    if not layers:
        raise ConfigError("no layers requested")
    for layer in layers:
        if layer not in VALID_LAYERS:
            raise ConfigError("unknown layer %r (valid: %s)"
                              % (layer, ", ".join(VALID_LAYERS)))
    return layers


def _delta_findings(deltas, status):
    out = []
    for key, value in deltas.get("findings", {}).items():
        if value != status:
            continue
        vuln_id, _, asset_id = key.partition("|")
        out.append({"vuln_id": vuln_id, "asset_key": asset_id,
                    "status": status})
    out.sort(key=lambda item: (item["asset_key"], item["vuln_id"]))
    return out


def cmd_scan(args, cfg):
    warnings = []
    started_iso = state.now_iso()
    started = time.time()
    layers = parse_layers(args.layers) if args.layers else list(cfg["layers"])
    floor_label = args.severity_floor or cfg["severity_floor"]
    floor_rank = match.severity_rank_from_label(floor_label)

    assets_cfg = inventory.load_assets_config(resolve(cfg["assets_file"]),
                                              warnings)
    assets, info = inventory.build_inventory(layers, assets_cfg, warnings)

    srcs = sources.build_sources(cfg, PROJECT_ROOT, warnings)
    per_source = []
    source_names = []
    for src in srcs:
        source_names.append(getattr(src, "name", src.__class__.__name__))
        try:
            per_source.append(src.fetch_findings(assets, warnings))
        except sources.SourceError as exc:
            warnings.append("source %s failed: %s"
                            % (getattr(src, "name", "?"), exc))
            per_source.append([])
    findings = sources.merge_findings(per_source)
    # The floor only filters reporting; state tracks everything.
    visible = [f for f in findings if f["severity_rank"] >= floor_rank]

    state_path = None if args.no_state else resolve(cfg["output"]["state_file"])
    if state_path:
        st = state.load_state(state_path, warnings)
        deltas = state.update_state(st, assets, findings)
        state.save_state(state_path, st)
    else:
        deltas = {"assets": {}, "findings": {}}

    resolved = _delta_findings(deltas, "resolved")
    gone = _delta_findings(deltas, "gone")

    metadata = {
        "started": started_iso,
        "finished": state.now_iso(),
        "duration_seconds": round(time.time() - started, 2),
        "host_id": cfg.get("host_id") or socket.gethostname(),
        "os_release_id": info["os_release"].get("ID"),
        "os_pretty_name": info["os_release"].get("PRETTY_NAME"),
        "python": "%d.%d.%d" % sys.version_info[:3],
        "layers": layers,
        "sources": source_names,
        "severity_floor": floor_label,
        "state_file": state_path,
        "warnings": warnings[:200],
    }
    summary = report.build_summary(assets, visible,
                                   state.delta_counts(deltas))
    reports_dir = resolve(cfg["output"]["reports_dir"])
    json_path, md_path = report.write_reports(reports_dir, metadata, summary,
                                              visible, resolved, gone)

    if args.json:
        with open(json_path, encoding="utf-8") as fh:
            sys.stdout.write(fh.read())
    else:
        by_layer = ", ".join("%s=%d" % item
                             for item in sorted(summary["assets_by_layer"].items()))
        print("vulncheck: scanned %d asset(s) (%s)"
              % (summary["assets_total"], by_layer or "none"))
        sev = summary["by_severity"]
        print("active findings: %d (critical=%d high=%d medium=%d low=%d "
              "none=%d)" % (summary["findings_total"], sev.get("critical", 0),
                            sev.get("high", 0), sev.get("medium", 0),
                            sev.get("low", 0), sev.get("none", 0)))
        for finding in sorted(visible, key=lambda f: (-f["severity_rank"],
                                                      f["vuln_id"],
                                                      f["asset_key"]))[:10]:
            print("  [%s] %s on %s (%s)"
                  % (match.severity_label(finding["severity_rank"]),
                     finding["vuln_id"], finding["asset_key"],
                     finding.get("source", "")))
        print("reports: %s , %s" % (json_path, md_path))
        for warning in warnings[:10]:
            print("warning: %s" % warning, file=sys.stderr)
        if len(warnings) > 10:
            print("... %d more warning(s) in the report"
                  % (len(warnings) - 10), file=sys.stderr)
    return 0


def cmd_inventory(args, cfg):
    warnings = []
    layers = parse_layers(args.layers) if args.layers else list(cfg["layers"])
    assets_cfg = inventory.load_assets_config(resolve(cfg["assets_file"]),
                                              warnings)
    assets, info = inventory.build_inventory(layers, assets_cfg, warnings)
    if args.json:
        print(json.dumps({"ecosystem": info["ecosystem"],
                          "os_pretty_name": info["os_release"].get("PRETTY_NAME"),
                          "assets": assets,
                          "warnings": warnings}, indent=2))
    else:
        counts = {}
        for asset in assets:
            counts[asset["layer"]] = counts.get(asset["layer"], 0) + 1
        print("ecosystem: %s" % (info["ecosystem"] or "unknown"))
        print("assets: %d (%s)" % (len(assets),
                                   ", ".join("%s=%d" % item for item
                                             in sorted(counts.items()))
                                   or "none"))
        for warning in warnings:
            print("warning: %s" % warning, file=sys.stderr)
    return 0


def cmd_status(args, cfg):
    path = resolve(cfg["output"]["state_file"])
    if not os.path.exists(path):
        print("no state file yet at %s (run a scan first)" % path)
        return 0
    warnings = []
    st = state.load_state(path, warnings)
    assets = st.get("assets", {})
    findings = st.get("findings", {})
    present = sum(1 for a in assets.values() if a.get("present"))
    active = sum(1 for f in findings.values() if f.get("active"))
    print("state file: %s" % path)
    print("assets tracked: %d (present: %d)" % (len(assets), present))
    print("findings recorded: %d (active: %d)" % (len(findings), active))
    for warning in warnings:
        print("warning: %s" % warning, file=sys.stderr)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vulncheck",
        description="Read-only vulnerability checker for local assets.")
    parser.add_argument("command", nargs="?", default="scan",
                        choices=("scan", "inventory", "status"))
    parser.add_argument("-c", "--config", default=None,
                        help="path to vulncheck.json")
    parser.add_argument("--layers", default=None,
                        help="comma-separated layers: os,python,container")
    parser.add_argument("--no-state", action="store_true",
                        help="do not load or update state")
    parser.add_argument("--severity-floor", default=None,
                        choices=FLOOR_CHOICES,
                        help="minimum severity to report")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config or default_config_path())
    except ConfigError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.command == "scan":
        return cmd_scan(args, cfg)
    if args.command == "inventory":
        return cmd_inventory(args, cfg)
    return cmd_status(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
