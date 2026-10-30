"""Vulnerability source clients and finding merge logic."""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from vulncheck import inventory, match


class SourceError(Exception):
    """A vulnerability source could not be queried."""


_RETRYABLE_STATUS = frozenset((429, 500, 502, 503, 504))


def _http_json(url, data=None, method=None, headers=None,
               timeout=30.0, retries=2):
    """POST/GET JSON with retry + exponential backoff on 429/5xx/network."""
    body = None
    send_headers = {"User-Agent": "vulncheck/0.1"}
    if headers:
        send_headers.update(headers)
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        send_headers.setdefault("Content-Type", "application/json")
    backoff = 1.0
    attempt = 0
    while True:
        req = urllib.request.Request(url, data=body, method=method,
                                     headers=send_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read().decode("utf-8")
            try:
                return json.loads(payload)
            except ValueError as exc:
                raise SourceError("invalid JSON from %s: %s" % (url, exc))
        except urllib.error.HTTPError as exc:
            if exc.code in _RETRYABLE_STATUS and attempt < retries:
                time.sleep(backoff)
                backoff *= 2
                attempt += 1
                continue
            raise SourceError("HTTP %s from %s" % (exc.code, url))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < retries:
                time.sleep(backoff)
                backoff *= 2
                attempt += 1
                continue
            raise SourceError("network error for %s: %s" % (url, exc))


def _severity_from_fields(entry):
    """Best severity rank/detail from a loose in-house finding mapping."""
    best_rank, best_detail = 0, ""
    vector = entry.get("cvss")
    if isinstance(vector, str) and vector.strip().upper().startswith("CVSS:"):
        score = match.cvss3_base_score(vector)
        if score is not None:
            rank = match.severity_rank_from_score(score)
            best_rank = rank
            best_detail = "%s -> %s (%s)" % (vector.strip(), score,
                                             match.severity_label(rank))
    numeric = entry.get("score")
    if numeric is not None and best_rank == 0:
        rank = match.severity_rank_from_score(numeric)
        if rank:
            best_rank = rank
            best_detail = "score %s (%s)" % (numeric, match.severity_label(rank))
    label = entry.get("severity")
    if label is not None and best_rank == 0:
        rank = match.severity_rank_from_label(label)
        best_rank = rank
        best_detail = "severity %s" % (label,)
    return best_rank, best_detail or "no severity information"


class InHouseSource:
    """Queries an in-house vulnerability service with the asset list."""

    def __init__(self, cfg):
        self.name = cfg.get("name", "in-house")
        self.url = cfg.get("url") or ""
        self.timeout = float(cfg.get("timeout", 30))
        self.retries = int(cfg.get("retries", 2))

    def fetch_findings(self, assets, warnings):
        if not self.url:
            warnings.append("in-house source %r has no url configured; "
                            "skipping" % self.name)
            return []
        payload = {"assets": [{
            "id": inventory.asset_key(a),
            "ecosystem": a.get("ecosystem"),
            "name": a["name"],
            "version": a["version"],
        } for a in assets]}
        try:
            resp = _http_json(self.url, data=payload, method="POST",
                              timeout=self.timeout, retries=self.retries)
        except SourceError as exc:
            raise SourceError("in-house source %r: %s" % (self.name, exc))
        if not isinstance(resp, dict):
            raise SourceError("in-house source %r returned a non-object "
                              "response" % self.name)
        entries = resp.get("vulnerabilities") or resp.get("findings") or []
        known = {inventory.asset_key(a) for a in assets}
        findings = []
        skipped = 0
        for entry in entries:
            if not isinstance(entry, dict):
                skipped += 1
                continue
            vuln_id = entry.get("id") or entry.get("vuln_id") or entry.get("key")
            asset_id = entry.get("asset_id") or entry.get("asset")
            if not vuln_id or asset_id not in known:
                skipped += 1
                continue
            rank, detail = _severity_from_fields(entry)
            findings.append({
                "vuln_id": str(vuln_id),
                "source": self.name,
                "asset_key": asset_id,
                "severity_rank": rank,
                "severity_detail": detail,
                "summary": entry.get("summary") or entry.get("title") or "",
                "description": entry.get("description") or "",
                "references": entry.get("references") or [],
            })
        if skipped:
            warnings.append("in-house source %r: skipped %d malformed or "
                            "unknown-asset finding(s)" % (self.name, skipped))
        return findings


class OSVSource:
    """osv.dev source: batched queries plus per-record fetch with cache."""

    def __init__(self, cfg, cache_root):
        self.name = cfg.get("name", "osv")
        self.base_url = (cfg.get("base_url") or "https://api.osv.dev").rstrip("/")
        self.batch_size = max(1, int(cfg.get("batch_size", 500)))
        self.timeout = float(cfg.get("timeout", 30))
        self.retries = int(cfg.get("retries", 2))
        self.max_workers = max(1, int(cfg.get("max_workers", 8)))
        self.cache_dir = cfg.get("cache_dir") or "cache/osv_vulns"
        if not os.path.isabs(self.cache_dir):
            self.cache_dir = os.path.join(cache_root, self.cache_dir)
        self.ttl_seconds = float(cfg.get("cache_ttl_days", 7)) * 86400.0
        os.makedirs(self.cache_dir, exist_ok=True)

    def _cache_path(self, vuln_id):
        quoted = urllib.parse.quote(vuln_id, safe="")
        return os.path.join(self.cache_dir, quoted + ".json")

    def _post(self, path, payload):
        return _http_json(self.base_url + path, data=payload, method="POST",
                          timeout=self.timeout, retries=self.retries)

    def _get_record(self, vuln_id, warnings):
        path = self._cache_path(vuln_id)
        try:
            if os.path.exists(path) and \
                    time.time() - os.path.getmtime(path) <= self.ttl_seconds:
                with open(path, encoding="utf-8") as fh:
                    return json.load(fh)
        except (OSError, ValueError):
            pass
        url = "%s/v1/vulns/%s" % (self.base_url,
                                  urllib.parse.quote(vuln_id, safe=""))
        try:
            record = _http_json(url, timeout=self.timeout,
                                retries=self.retries)
        except SourceError as exc:
            warnings.append("osv: %s" % exc)
            return None
        tmp = path + ".tmp.%d" % os.getpid()
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(record, fh)
            os.replace(tmp, path)
        except OSError:
            pass
        return record

    def fetch_findings(self, assets, warnings):
        queries, q_assets = [], []
        seen = set()
        for asset in assets:
            eco = asset.get("ecosystem")
            if not eco:
                continue
            qkey = (eco.lower(), asset["name"].lower(), asset["version"])
            if qkey in seen:
                continue
            seen.add(qkey)
            queries.append({"package": {"name": asset["name"],
                                        "ecosystem": eco},
                            "version": asset["version"]})
            q_assets.append(asset)
        if not queries:
            return []

        pairs = []  # (vuln_id, asset)
        for start in range(0, len(queries), self.batch_size):
            batch = queries[start:start + self.batch_size]
            try:
                resp = self._post("/v1/querybatch", {"queries": batch})
            except SourceError as exc:
                raise SourceError("osv: %s" % exc)
            results = resp.get("results") or []
            if len(results) != len(batch):
                warnings.append(
                    "osv: querybatch returned %d result(s) for %d queries"
                    % (len(results), len(batch)))
            for offset, res in enumerate(results):
                asset = q_assets[start + offset]
                for stub in (res or {}).get("vulns") or []:
                    vuln_id = stub.get("id")
                    if vuln_id:
                        pairs.append((vuln_id, asset))
        if not pairs:
            return []

        unique_ids = sorted({vid for vid, _ in pairs})

        def fetch(vid):
            return vid, self._get_record(vid, warnings)

        records = {}
        failed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(fetch, vid) for vid in unique_ids]
            for fut in as_completed(futures):
                vid, record = fut.result()
                if record is None:
                    failed += 1
                else:
                    records[vid] = record
        if failed:
            warnings.append("osv: failed to fetch %d record(s)" % failed)

        findings = []
        undecided = 0
        for vid, asset in pairs:
            record = records.get(vid)
            if record is None:
                continue
            hit = match.osv_record_matches_asset(
                record, asset.get("ecosystem"), asset["name"],
                asset["version"])
            if hit is True:
                findings.append(self._finding(vid, record, asset))
            elif hit is None:
                undecided += 1
        if undecided:
            warnings.append("osv: %d version match(es) could not be decided"
                            % undecided)
        return findings

    def _finding(self, vuln_id, record, asset):
        rank, detail = match.extract_severity(record)
        refs = []
        for ref in record.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(ref["url"])
            elif isinstance(ref, str):
                refs.append(ref)
        summary = record.get("summary") or ""
        details = record.get("details") or ""
        return {
            "vuln_id": vuln_id,
            "source": self.name,
            "asset_key": inventory.asset_key(asset),
            "severity_rank": rank,
            "severity_detail": detail,
            "summary": summary or (details[:200] if details else ""),
            "description": details,
            "references": refs,
            "url": "https://osv.dev/vulnerability/%s" % urllib.parse.quote(
                vuln_id, safe=""),
        }


def build_sources(config, project_root, warnings):
    """Instantiate enabled sources in priority order."""
    sources = []
    for cfg in config.get("sources") or []:
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            continue
        stype = cfg.get("type")
        if stype == "in-house":
            sources.append(InHouseSource(cfg))
        elif stype == "osv":
            sources.append(OSVSource(cfg, project_root))
        else:
            warnings.append("unknown source type %r ignored" % (stype,))
    sources.sort(key=lambda s: 0)
    return sources


def merge_findings(finding_lists):
    """Merge per-source findings; first source wins, later ones recorded.

    Merge key is (vuln_id, asset_key).  Severity is the maximum across
    duplicates so a severity-less first record cannot understate risk.
    """
    merged = {}
    order = []
    for findings in finding_lists:
        for finding in findings:
            key = (finding["vuln_id"], finding["asset_key"])
            if key not in merged:
                entry = dict(finding)
                entry.setdefault("also_reported_by", [])
                merged[key] = entry
                order.append(key)
                continue
            kept = merged[key]
            src = finding.get("source")
            if src and src not in kept["also_reported_by"] and \
                    src != kept.get("source"):
                kept["also_reported_by"].append(src)
            if finding["severity_rank"] > kept["severity_rank"]:
                kept["severity_rank"] = finding["severity_rank"]
                kept["severity_detail"] = finding["severity_detail"]
    return [merged[key] for key in order]
