"""Local asset inventory: OS (dpkg), Python distributions, container stub."""

import json
import os
import re
from importlib import metadata as importlib_metadata

from vulncheck import match

_DPKG_STATUS = "/var/lib/dpkg/status"
_OS_RELEASE = "/etc/os-release"
_DOCKER_SOCKET = "/var/run/docker.sock"

_SOURCE_FIELD_RE = re.compile(r"^(\S+)(?:\s+\(([^)]*)\))?$")


def read_os_release(path=_OS_RELEASE):
    """Parse /etc/os-release into a dict (empty on failure)."""
    data = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return data


def osv_ecosystem_from_os_release(data):
    """Map /etc/os-release data to an OSV ecosystem name (Ubuntu only)."""
    os_id = (data.get("ID") or "").strip().lower()
    version_id = (data.get("VERSION_ID") or "").strip()
    if os_id == "ubuntu" and version_id:
        return "Ubuntu:" + version_id
    return None


def parse_source_field(value):
    """Split a dpkg Source field like 'openssl (1.2.3-1)' into name/version."""
    m = _SOURCE_FIELD_RE.match(value.strip())
    if not m:
        return value.strip(), None
    return m.group(1), m.group(2)


def parse_dpkg_status(path=_DPKG_STATUS):
    """Parse the dpkg status database into entries for installed packages."""
    entries = []
    stanza = {}

    def flush():
        if not stanza.get("Package") or not stanza.get("Version"):
            return
        if stanza.get("Status", "install ok installed").strip() != \
                "install ok installed":
            return
        entry = {"name": stanza["Package"], "version": stanza["Version"]}
        if stanza.get("Source"):
            sname, sver = parse_source_field(stanza["Source"])
            entry["source_name"] = sname
            if sver:
                entry["source_version"] = sver
        entries.append(entry)

    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return []
    with fh:
        stanza = {}
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                flush()
                stanza = {}
                continue
            if line[0] in " \t":
                continue  # folded continuation lines: not needed
            key, sep, value = line.partition(":")
            if sep:
                stanza[key.strip()] = value.strip()
        flush()
    return entries


def os_assets(status_path=_DPKG_STATUS, ecosystem=None):
    """One asset per source package (OSV indexes source packages).

    The Source field maps binaries like libssl3 to source openssl; the
    query uses (source_name, source_version), falling back to the
    binary identity.  Multiple binaries per source are deduplicated,
    keeping the highest version under dpkg ordering.
    """
    if ecosystem is None:
        return []
    best = {}
    for entry in parse_dpkg_status(status_path):
        name = entry.get("source_name") or entry["name"]
        version = entry.get("source_version") or entry["version"]
        prev = best.get(name)
        if prev is not None:
            try:
                better = match.dpkg_compare_strings(version, prev[0]) > 0
            except match.DpkgParseError:
                better = False
            if not better:
                continue
        best[name] = (version, entry)
    assets = []
    for name in sorted(best):
        version, entry = best[name]
        assets.append({
            "layer": "os",
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "binary_name": entry["name"],
            "binary_version": entry["version"],
        })
    return assets


def python_assets():
    """Installed Python distributions (deduplicated by canonical name)."""
    assets = []
    seen = set()
    for dist in importlib_metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.metadata["Version"]
        except Exception:
            continue
        if not name or not version:
            continue
        norm = normalize_name("python", name)
        if norm in seen:
            continue
        seen.add(norm)
        assets.append({"layer": "python", "ecosystem": "PyPI",
                       "name": name, "version": version})
    return assets


def container_assets(assets_config, warnings):
    """Container layer stub: never inventories, only warns."""
    cfg = (assets_config or {}).get("container") or {}
    if not cfg.get("enabled"):
        return []
    images = cfg.get("images") or []
    if os.path.exists(_DOCKER_SOCKET):
        warnings.append(
            "container layer is a stub: docker socket found but image "
            "scanning is not implemented (%d configured image(s) skipped)"
            % len(images))
    else:
        warnings.append(
            "container layer unavailable: no docker daemon socket at %s "
            "(%d configured image(s) skipped)" % (_DOCKER_SOCKET, len(images)))
    return []


def load_assets_config(path, warnings):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        warnings.append("could not read assets file %s: %s" % (path, exc))
        return {}


def _extra_assets(assets_config, warnings):
    """Manually configured assets from config/assets.json."""
    out = []
    for raw in (assets_config or {}).get("extra_assets") or []:
        if not isinstance(raw, dict):
            warnings.append("ignoring non-object extra asset entry")
            continue
        layer = raw.get("layer")
        name = raw.get("name")
        version = raw.get("version")
        if layer not in ("os", "python") or not name or not version:
            warnings.append("ignoring invalid extra asset entry: %r" % (raw,))
            continue
        ecosystem = raw.get("ecosystem") or ("PyPI" if layer == "python"
                                             else None)
        out.append({"layer": layer, "ecosystem": ecosystem,
                    "name": name, "version": version})
    return out


def normalize_name(layer, name):
    name = (name or "").strip()
    if layer == "python":
        return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503
    return name.lower()


def asset_key(asset):
    """Stable identifier for state tracking: '<layer>:<normalized name>'."""
    return "%s:%s" % (asset["layer"], normalize_name(asset["layer"],
                                                     asset["name"]))


def build_inventory(layers, assets_config, warnings):
    """Build the asset list for the requested layers.

    Returns (assets, info) where info carries os-release details for
    the report metadata.
    """
    os_release = read_os_release()
    ecosystem = osv_ecosystem_from_os_release(os_release)
    info = {"os_release": os_release, "ecosystem": ecosystem}
    assets = []
    if "os" in layers:
        if ecosystem is None:
            warnings.append("could not determine an Ubuntu release from "
                            "/etc/os-release; skipping os layer")
        else:
            assets.extend(os_assets(ecosystem=ecosystem))
    if "python" in layers:
        assets.extend(python_assets())
    if "container" in layers:
        assets.extend(container_assets(assets_config, warnings))
    assets.extend(_extra_assets(assets_config, warnings))
    return assets, info
