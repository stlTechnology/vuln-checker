# Vuln Checker

Project folder for checking systems and software for known vulnerabilities.

## Goal

To be defined. Candidate scopes include checking installed software or dependency
versions against vulnerability databases, or reviewing scanner findings for
systems we own or are authorized to assess.

## Open questions

- What to check: OS and packages, application dependencies, container images, or network-facing services
- Targets: which hosts, repos, or images are in scope, and who authorized the checks
- Data sources: NVD, OSV, GitHub Advisory Database, vendor advisories, or an existing scanner export
- Output: report format (CSV, JSON, or a dashboard) and who receives it
- Cadence: one-off assessment or a recurring job

## Plan (draft)

1. Define the in-scope assets and the authorization for checking them
2. Pick the data sources and the matching method (version, CPE, or package-level)
3. Write a checker that normalizes findings and removes duplicates
4. Produce a report ranked by severity and exploitability
5. Track fixes and re-check on a schedule

## Layout

- `README.md`: this file
- `docs/`: scope, data-source notes, decisions
- `scripts/`: checker and report scripts
- `config/`: configuration templates (no credentials)
