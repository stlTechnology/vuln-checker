"""Version matching, severity scoring, and OSV record matching for vulncheck.

The Debian version comparator is a faithful port of dpkg 1.21.1
(lib/dpkg/version.c: order() + verrevcmp(); lib/dpkg/parsehelp.c:
parseversion()), verified against `dpkg --compare-versions` and the
official deb-version(7) sorting algorithm.
"""

import re
from decimal import Decimal, ROUND_CEILING, InvalidOperation
from typing import List, NamedTuple, Optional, Tuple

__all__ = [
    "DpkgVersion",
    "DpkgParseError",
    "parse_dpkg_version",
    "dpkg_version_compare",
    "dpkg_relate",
    "UbuntuComparator",
    "PypiComparator",
    "comparator_for",
    "ecosystem_matches",
    "version_affected",
    "osv_record_matches_asset",
    "cvss3_base_score",
    "severity_rank_from_score",
    "severity_rank_from_label",
    "severity_label",
    "extract_severity",
]

_D = Decimal
_CENT = Decimal("0.1")
INT_MAX = 2147483647  # dpkg rejects epochs above C INT_MAX (parsehelp.c)


class DpkgVersion(NamedTuple):
    epoch: int
    version: str
    revision: str


class DpkgParseError(ValueError):
    """Hard version syntax error (dpkg would exit 2 for these)."""


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_alpha(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


# ---------------------------------------------------------------------------
# Parsing (port of parseversion() from lib/dpkg/parsehelp.c, dpkg 1.21.1)
# ---------------------------------------------------------------------------

def parse_dpkg_version(string: str) -> DpkgVersion:
    """Parse a Debian version string like dpkg's parseversion().

    Hard syntax errors raise DpkgParseError.  Conditions dpkg only
    warns about (upstream not starting with a digit, invalid characters
    such as ``_``) are accepted silently, matching the behaviour of
    ``dpkg --compare-versions``.  The dpkg CLI treats an empty argument
    as a blank version (epoch 0, empty upstream and revision), so an
    empty string is accepted here as well.
    """
    if string == "":
        return DpkgVersion(0, "", "")

    # Trim leading blanks (space and tab only, like c_isblank()).
    s = string.lstrip(" \t")
    if not s:
        raise DpkgParseError("version string is empty")

    # The version is everything up to the first blank; any non-blank
    # after trailing blanks is an embedded-space error.
    end = 0
    n = len(s)
    while end < n and s[end] not in " \t":
        end += 1
    if s[end:].strip(" \t"):
        raise DpkgParseError("version string has embedded spaces")
    s = s[:end]

    epoch = 0
    colon = s.find(":")
    if colon != -1:
        epoch, rest = _parse_epoch(s, colon)
        if not rest:
            raise DpkgParseError("nothing after colon in version number")
    else:
        rest = s

    # Split at the LAST hyphen, if any.
    hyphen = rest.rfind("-")
    if hyphen != -1:
        upstream = rest[:hyphen]
        revision = rest[hyphen + 1:]
        if revision == "":
            raise DpkgParseError("revision number is empty")
    else:
        upstream = rest
        revision = ""

    if upstream == "":
        raise DpkgParseError("version number is empty")

    # Conditions dpkg only warns about (non-fatal):
    #  - upstream version does not start with a digit
    #  - invalid characters in upstream / revision
    # (No behaviour change; kept implicit.  See parsehelp.c.)
    return DpkgVersion(epoch, upstream, revision)


def _parse_epoch(s: str, colon: int) -> Tuple[int, str]:
    """Parse the epoch prefix of s[:colon]; returns (epoch, remainder).

    Mirrors strtol() semantics used by parseversion(): optional sign
    followed by digits; anything else before the colon is an error.
    """
    num = s[:colon]
    i = 0
    if num and num[0] in "+-":
        i = 1
    start = i
    while i < len(num) and _is_digit(num[i]):
        i += 1
    digits = num[start:i]
    if not digits:
        raise DpkgParseError("epoch in version is empty")
    if i != len(num):
        raise DpkgParseError("epoch in version is not number")
    value = int(num[:i])
    if value < 0:
        raise DpkgParseError("epoch in version is negative")
    if value > INT_MAX:
        raise DpkgParseError("epoch in version is too big")
    return value, s[colon + 1:]


# ---------------------------------------------------------------------------
# Comparison (port of order() + verrevcmp() from lib/dpkg/version.c)
# ---------------------------------------------------------------------------

def _order(c: str) -> int:
    """Sort weight of a character in version comparison.

    digit -> 0, alpha -> ASCII value, '~' -> -1, other -> ASCII + 256,
    end of part (NUL) -> 0.  Hence '~' < digits/end < letters < other
    non-alphanumerics.
    """
    if c == "":
        return 0
    if _is_digit(c):
        return 0
    if _is_alpha(c):
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Port of verrevcmp() from lib/dpkg/version.c (dpkg 1.21.1)."""
    la, lb = len(a), len(b)
    i = j = 0
    while i < la or j < lb:
        first_diff = 0

        # Compare the non-digit prefixes character by character.
        while (i < la and not _is_digit(a[i])) or (j < lb and not _is_digit(b[j])):
            ac = _order(a[i] if i < la else "")
            bc = _order(b[j] if j < lb else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1

        # Skip leading zeros on both sides independently.
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1

        # Scan digit runs in parallel, remembering the first difference.
        while i < la and j < lb and _is_digit(a[i]) and _is_digit(b[j]):
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1

        # A longer digit run wins, regardless of first_diff (so 2 < 10).
        if i < la and _is_digit(a[i]):
            return 1
        if j < lb and _is_digit(b[j]):
            return -1
        if first_diff:
            return first_diff

    return 0


def dpkg_version_compare(a: DpkgVersion, b: DpkgVersion) -> int:
    """Port of dpkg_version_compare(): epoch, upstream, then revision."""
    if a.epoch > b.epoch:
        return 1
    if a.epoch < b.epoch:
        return -1
    rc = _verrevcmp(a.version, b.version)
    if rc:
        return rc
    return _verrevcmp(a.revision, b.revision)


_RELATIONS = {
    "lt": lambda rc: rc < 0,
    "le": lambda rc: rc <= 0,
    "eq": lambda rc: rc == 0,
    "ne": lambda rc: rc != 0,
    "gt": lambda rc: rc > 0,
    "ge": lambda rc: rc >= 0,
}
_SYMBOLIC = {
    "<<": "lt", "<": "le", "<=": "le",
    "=": "eq", "==": "eq",
    ">": "ge", ">=": "ge", ">>": "gt",
}


def dpkg_relate(a: str, op: str, b: str) -> bool:
    """Compare version strings a and b under a dpkg relation operator.

    Accepts lt/le/eq/ne/gt/ge and the symbolic forms used by OSV Debian
    ranges (<, <=, =, >, >=).  Raises DpkgParseError if either version
    has a hard syntax error.
    """
    key = _SYMBOLIC.get(op, op)
    test = _RELATIONS.get(key)
    if test is None:
        raise ValueError("unknown relation operator: %r" % (op,))
    return test(dpkg_version_compare(parse_dpkg_version(a), parse_dpkg_version(b)))


def dpkg_compare_strings(a: str, b: str) -> int:
    """Convenience: parse both strings and return the comparison sign."""
    return dpkg_version_compare(parse_dpkg_version(a), parse_dpkg_version(b))


# ---------------------------------------------------------------------------
# Ecosystem comparators
# ---------------------------------------------------------------------------

class UbuntuComparator:
    """Debian/dpkg version ordering (Ubuntu and Debian ecosystems)."""

    name = "dpkg"

    def compare(self, a: str, b: str) -> Optional[int]:
        try:
            return dpkg_compare_strings(a, b)
        except DpkgParseError:
            return None


class PypiComparator:
    """Approximate PEP 440 ordering for the PyPI ecosystem.

    Returns None when either version cannot be interpreted ("cannot
    decide"); callers must treat that as "not affected" plus a warning.
    """

    name = "pep440-approx"

    _RELEASE_RE = re.compile(r"^v?(?P<rel>[0-9]+(?:\.[0-9]+)*)(?P<rest>.*)$")
    _SUFFIX_RANK = {
        "dev": 0,
        "a": 1, "alpha": 1,
        "b": 2, "beta": 2,
        "c": 3, "rc": 3, "pre": 3, "preview": 3,
        "": 4,
        "post": 5, "rev": 5, "r": 5,
    }
    _TOKEN_RE = re.compile(r"^(?P<word>[a-z]*)(?P<num>\d*)$")

    def key(self, version: str) -> Optional[tuple]:
        v = version.strip()
        v = v.split("+", 1)[0]  # drop local version segment
        epoch = 0
        if "!" in v:
            epoch_s, _, v = v.partition("!")
            if not epoch_s.isdigit():
                return None
            epoch = int(epoch_s)
        v = v.lower()
        m = self._RELEASE_RE.match(v)
        if not m:
            return None
        release = tuple(int(x) for x in m.group("rel").split("."))
        release = release + (0,) * (8 - len(release)) if len(release) < 8 else release
        suffixes: List[Tuple[int, int]] = []
        rest = m.group("rest").replace("_", "-").replace(".", "-")
        for token in [t for t in rest.split("-") if t]:
            tm = self._TOKEN_RE.match(token)
            if not tm or (not tm.group("word") and not tm.group("num")):
                return None
            word = tm.group("word")
            num = int(tm.group("num")) if tm.group("num") else 0
            if word not in self._SUFFIX_RANK:
                return None
            suffixes.append((self._SUFFIX_RANK[word], num))
        if not suffixes:
            suffixes = [(4, 0)]  # implicit "final" sorts between rc and post
        return (epoch, release, tuple(suffixes))

    def compare(self, a: str, b: str) -> Optional[int]:
        ka, kb = self.key(a), self.key(b)
        if ka is None or kb is None:
            return None
        if ka < kb:
            return -1
        if ka > kb:
            return 1
        return 0


_UBUNTU_LIKE = ("ubuntu", "debian")


def comparator_for(ecosystem: str):
    """Pick a comparator class for an OSV ecosystem name (may be None)."""
    eco = (ecosystem or "").strip().lower()
    base = eco.split(":")[0]
    if base in _UBUNTU_LIKE:
        return UbuntuComparator()
    if base in ("pypi",):
        return PypiComparator()
    return None


def ecosystem_matches(asset_ecosystem: str, record_ecosystem: str) -> bool:
    """True if an OSV record ecosystem applies to the asset's ecosystem.

    Case-insensitive exact match, or the Ubuntu release-suffix rule:
    ``Ubuntu:22.04`` matches ``Ubuntu:22.04`` and ``Ubuntu:22.04:LTS``.
    """
    a = (asset_ecosystem or "").strip().lower()
    r = (record_ecosystem or "").strip().lower()
    if not a or not r:
        return False
    if a == r:
        return True
    a_parts, r_parts = a.split(":"), r.split(":")
    if len(a_parts) >= 2 and len(r_parts) >= 2:
        if a_parts[0] in _UBUNTU_LIKE and r_parts[0] in _UBUNTU_LIKE:
            return a_parts[0] == r_parts[0] and a_parts[1] == r_parts[1]
    return False


# ---------------------------------------------------------------------------
# OSV affected-range matching
# ---------------------------------------------------------------------------

def version_affected(ecosystem: str, version: str, affected: dict) -> Optional[bool]:
    """Does `version` fall inside one OSV `affected` entry?

    Returns True/False, or None when the answer cannot be decided
    (unparseable version or range values).
    """
    versions = affected.get("versions")
    if versions:
        return version in versions  # explicit list is authoritative

    comparator = comparator_for(ecosystem)
    if comparator is None:
        return None

    for rng in affected.get("ranges") or []:
        rtype = rng.get("type")
        if rtype not in ("ECOSYSTEM", "SEMVER", "GENERIC"):
            continue
        introduced = "0"
        fixed = None
        for event in rng.get("events") or []:
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]

        if introduced != "*":
            low = comparator.compare(version, introduced)
            if low is None:
                return None
            if low < 0:
                continue
        if fixed not in (None, ""):
            high = comparator.compare(version, fixed)
            if high is None:
                return None
            if high >= 0:
                continue
        return True
    return False


def osv_record_matches_asset(record: dict, ecosystem: str, name: str,
                            version: str) -> Optional[bool]:
    """Does an OSV vulnerability record affect the given asset?

    Returns True/False, or None when matching could not be decided.
    Package names are matched exactly (OSV names for Ubuntu and PyPI
    are already lowercase).
    """
    result = False
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") != name:
            continue
        eco = pkg.get("ecosystem")
        if eco and not ecosystem_matches(ecosystem, eco):
            continue
        matched = version_affected(ecosystem, version, affected)
        if matched is None:
            return None
        if matched:
            result = True
    return result


# ---------------------------------------------------------------------------
# CVSS 3.1 base scoring (per the FIRST specification)
# ---------------------------------------------------------------------------

_AV = {"N": _D("0.85"), "A": _D("0.62"), "L": _D("0.55"), "P": _D("0.20")}
_AC = {"L": _D("0.77"), "H": _D("0.44")}
_PR_U = {"N": _D("0.85"), "L": _D("0.62"), "H": _D("0.27")}
_PR_C = {"N": _D("0.85"), "L": _D("0.68"), "H": _D("0.50")}
_UI = {"N": _D("0.85"), "R": _D("0.62")}
_CIA = {"H": _D("0.56"), "L": _D("0.22"), "N": _D("0")}


def cvss3_base_score(vector: str) -> Optional[Decimal]:
    """Compute a CVSS 3.1 base score from a vector string, or None.

    Only ``CVSS:3.0/`` and ``CVSS:3.1/`` vectors are accepted; anything
    malformed returns None so callers can fall back to other severity
    hints.
    """
    if not vector:
        return None
    parts = vector.strip().split("/")
    if parts[0].upper() not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = {}
    for part in parts[1:]:
        if not part:
            continue
        key, sep, value = part.partition(":")
        if (not sep or not key.isalpha() or not key.isupper()
                or len(key) > 2 or len(value) != 1):
            return None
        metrics[key] = value.upper()
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        s = metrics["S"]
        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]
        if s == "U":
            pr = _PR_U[metrics["PR"]]
        elif s == "C":
            pr = _PR_C[metrics["PR"]]
        else:
            return None
        ui = _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if s == "U":
        isc = _D("6.42") * isc_base
    else:
        isc = (_D("7.52") * (isc_base - _D("0.029"))
               - _D("3.25") * (isc_base - _D("0.02")) ** 15)
    if isc <= 0:
        isc = _D("0")
    esc = _D("8.22") * av * ac * pr * ui
    if s == "U":
        raw = min(isc + esc, _D("10"))
    else:
        raw = min(_D("1.08") * (isc + esc), _D("10"))
    try:
        return raw.quantize(_CENT, rounding=ROUND_CEILING)
    except InvalidOperation:
        return None


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

def severity_rank_from_score(score) -> int:
    """Map a numeric CVSS-style score to 0-4 (none/low/medium/high/critical)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return 0
    if value >= 9.0:
        return 4
    if value >= 7.0:
        return 3
    if value >= 4.0:
        return 2
    if value > 0.0:
        return 1
    return 0


_LABEL_RANKS = {
    "critical": 4,
    "high": 3, "important": 3,
    "medium": 2, "moderate": 2,
    "low": 1,
    "none": 0, "negligible": 0, "unknown": 0, "": 0,
}


def severity_rank_from_label(label) -> int:
    """Map a severity label (any case) to 0-4; unknown labels rank 0."""
    if label is None:
        return 0
    return _LABEL_RANKS.get(str(label).strip().lower(), 0)


_SEVERITY_NAMES = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def severity_label(rank: int) -> str:
    """Canonical severity label for a 0-4 rank."""
    return _SEVERITY_NAMES.get(int(rank), "unknown")


def extract_severity(record: dict) -> Tuple[int, str]:
    """Best severity rank (0-4) for an OSV record, with a detail string.

    Preference order: parseable CVSS 3.x vector > numeric score >
    severity label; the maximum rank found wins.
    """
    best_rank = 0
    best_detail = ""

    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        etype = str(entry.get("type", ""))
        score = entry.get("score")
        if etype.startswith("CVSS_V") and isinstance(score, str):
            numeric = cvss3_base_score(score)
            if numeric is not None:
                rank = severity_rank_from_score(numeric)
                detail = "%s -> %s (%s)" % (score, numeric, severity_label(rank))
                if rank > best_rank or not best_detail:
                    best_rank, best_detail = rank, detail
                continue
        if isinstance(score, (int, float)) or (
                isinstance(score, str) and score.replace(".", "", 1).isdigit()):
            rank = severity_rank_from_score(score)
            detail = "%s score %s (%s)" % (etype or "numeric", score,
                                           severity_label(rank))
        else:
            rank = severity_rank_from_label(score)
            detail = "%s label %s" % (etype or "label", score)
        if rank > best_rank or not best_detail:
            best_rank, best_detail = rank, detail

    db_sev = (record.get("database_specific") or {}).get("severity")
    if db_sev:
        rank = severity_rank_from_label(db_sev)
        detail = "database_specific.severity %s" % (db_sev,)
        if rank > best_rank or not best_detail:
            best_rank, best_detail = rank, detail

    if not best_detail:
        best_detail = "no severity information"
    return best_rank, best_detail
