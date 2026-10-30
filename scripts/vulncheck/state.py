"""Durable scan state and change deltas."""

import json
import os
import time

STATE_VERSION = 1


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fresh_state():
    return {"version": STATE_VERSION, "assets": {}, "findings": {}}


def load_state(path, warnings):
    """Load state from path; a missing or corrupt file yields fresh state."""
    if not path or not os.path.exists(path):
        return _fresh_state()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        warnings.append("could not read state file %s (%s); starting fresh"
                        % (path, exc))
        return _fresh_state()
    if not isinstance(data, dict):
        warnings.append("state file %s is not an object; starting fresh"
                        % path)
        return _fresh_state()
    st = _fresh_state()
    if isinstance(data.get("assets"), dict):
        st["assets"] = data["assets"]
    if isinstance(data.get("findings"), dict):
        st["findings"] = data["findings"]
    return st


def save_state(path, state):
    if not path:
        return
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp.%d" % os.getpid()
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def update_state(state, assets, active_findings):
    """Fold this scan into state; returns per-key deltas.

    Asset deltas: new, version_changed, reappeared, gone.
    Finding deltas: new, reopened, unchanged, resolved, gone.
    """
    now = now_iso()
    deltas = {"assets": {}, "findings": {}}
    current_assets = {}
    for asset in assets:
        current_assets[inventory_key(asset)] = asset

    st_assets = state["assets"]
    for key, asset in current_assets.items():
        prev = st_assets.get(key)
        if prev is None:
            deltas["assets"][key] = "new"
        elif not prev.get("present", True):
            deltas["assets"][key] = "reappeared"
        elif prev.get("last_version") != asset["version"]:
            deltas["assets"][key] = "version_changed"
        st_assets[key] = {
            "first_seen": (prev or {}).get("first_seen") or now,
            "last_seen": now,
            "last_version": asset["version"],
            "present": True,
        }
    for key, prev in st_assets.items():
        if key in current_assets:
            continue
        if prev.get("present", False):
            deltas["assets"][key] = "gone"
            prev["present"] = False
            prev["last_seen"] = now

    st_findings = state["findings"]
    current_findings = {}
    for finding in active_findings:
        current_findings[finding_key(finding)] = finding
    for key in current_findings:
        prev = st_findings.get(key)
        if prev is None:
            deltas["findings"][key] = "new"
        elif prev.get("active"):
            deltas["findings"][key] = "unchanged"
        else:
            deltas["findings"][key] = "reopened"
        st_findings[key] = {
            "first_seen": (prev or {}).get("first_seen") or now,
            "last_seen": now,
            "active": True,
        }
    for key, prev in st_findings.items():
        if key in current_findings:
            continue
        if not prev.get("active"):
            continue
        asset_id = key.split("|", 1)[1]
        if asset_id in current_assets:
            deltas["findings"][key] = "resolved"
        else:
            deltas["findings"][key] = "gone"
        prev["active"] = False
        prev["last_seen"] = now
    return deltas


def inventory_key(asset):
    from vulncheck.inventory import asset_key
    return asset_key(asset)


def finding_key(finding):
    return "%s|%s" % (finding["vuln_id"], finding["asset_key"])


def delta_counts(deltas):
    return {
        "assets": _tally(deltas.get("assets", {})),
        "findings": _tally(deltas.get("findings", {})),
    }


def _tally(mapping):
    counts = {}
    for value in mapping.values():
        counts[value] = counts.get(value, 0) + 1
    return counts
