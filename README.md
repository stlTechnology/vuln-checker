# vuln-checker

A **read-only, stdlib-only, pluggable vulnerability checker** for local
hosts. It inventories installed OS packages (Ubuntu/dpkg) and Python
distributions, matches them against vulnerability sources (osv.dev by
default, plus an optional in-house service), and produces
severity-ranked JSON/Markdown reports with durable state and
change tracking between scans.

## Why

Existing scanners (trivy, grype, osv-scanner) are excellent but bring
runtimes, containers, or non-stdlib dependencies. This tool is a single
Python 3.10+ codebase with **zero third-party dependencies**, safe to
run on production hosts: it only reads package databases and makes
outbound HTTPS calls to the configured sources.

## Usage

```console
$ python3 scripts/vulncheck.py                 # scan (default command)
$ python3 scripts/vulncheck.py scan --json     # machine-readable report on stdout
$ python3 scripts/vulncheck.py scan --layers os,python --no-state
$ python3 scripts/vulncheck.py inventory       # what would be scanned
$ python3 scripts/vulncheck.py status          # what state is tracked
```

Exit codes: `0` for any completed scan (findings are not errors),
`2` only for fatal configuration problems. Source outages degrade to
warnings, never crashes.

Outputs: `reports/scan.json`, `reports/scan.md`, state in
`state/state.json`, OSV record cache in `cache/osv_vulns/` (7-day TTL).

## Configuration

`config/vulncheck.json` (paths relative to the project root):

```json
{
  "host_id": null,
  "layers": ["os", "python", "container"],
  "severity_floor": "none",
  "sources": [
    {"name": "in-house", "type": "in-house", "enabled": false, "url": ""},
    {"name": "osv", "type": "osv", "enabled": true,
     "base_url": "https://api.osv.dev", "batch_size": 500,
     "cache_dir": "cache/osv_vulns", "cache_ttl_days": 7,
     "timeout": 30, "retries": 2, "max_workers": 8}
  ],
  "output": {"reports_dir": "reports", "state_file": "state/state.json"}
}
```

- **Source order is priority order**: the first source that reports a
  (vuln, asset) pair wins; later duplicates are recorded in
  `also_reported_by`. Severity is the maximum across duplicates.
- `severity_floor`: `none|low|medium|high|critical`. Findings with no
  usable severity information rank `0`, which is why the default floor
  is `none` — raising it hides unknown-severity findings too.
- `config/assets.json`: `extra_assets` (manual `{layer, ecosystem,
  name, version}` entries) and the `container` stub config. No
  credentials ever belong in config.

### In-house source contract

`POST url` with `{"assets": [{"id": "os:curl", "ecosystem":
"Ubuntu:22.04", "name": "curl", "version": "..."}]}`; expects
`{"vulnerabilities": [{"id", "asset_id", "severity"|"cvss"|"score",
"summary", "description"?, "references"?}]}`. Findings referencing
unknown asset ids are warned about and skipped.

## How matching works

- **Ubuntu/Debian versions** use a faithful port of dpkg 1.21.1
  (`lib/dpkg/version.c`, `lib/dpkg/parsehelp.c`), verified against
  dpkg's own test vectors, 2500+ fuzz pairs against the live
  `dpkg --compare-versions`, and `apt_pkg.version_compare`.
  The epoch is capped at INT_MAX like dpkg; syntax errors are treated
  as "cannot decide", not crashes.
- **OSV affected matching**: an explicit `affected[].versions` list is
  authoritative; otherwise `ECOSYSTEM`/`SEMVER`/`GENERIC` ranges
  (`introduced`/`fixed`) with the ecosystem's comparator. Ubuntu
  release suffixes (`Ubuntu:22.04` vs `Ubuntu:22.04:LTS`) match.
- **PyPI versions** use an approximate PEP 440 sortable key
  (epoch, zero-padded release, dev/alpha/beta/rc/final/post ranks).
  Unparseable versions yield "cannot decide" → not affected + warning.
- **Severity**: CVSS 3.1 base scores are computed from vectors with
  `Decimal` (spec canonical examples verified); labels like
  `medium`/`important`/`negligible` map to a 0–4 rank; the maximum
  across a record's severity entries wins.

## Limitations

- The container layer is a stub: it warns and inventories nothing
  (no docker client in stdlib-land; wire in trivy/grype output later).
- OS packages are matched at *source-package* granularity (OSV indexes
  source packages); systems that are fully patched will legitimately
  report zero findings.
- System Python packages (e.g. python-apt) appear in the PyPI layer
  with distro version strings; they are reported as "cannot decide"
  rather than guessed at.

## Development

```console
$ python3 scripts/tests/test_match.py   # unit tests incl. live-dpkg fuzz
```

Layout: `scripts/vulncheck/` (match, inventory, sources, state,
report), `scripts/vulncheck.py` (CLI), `scripts/tests/`, `docs/`.
