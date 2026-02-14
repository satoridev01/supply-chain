#!/usr/bin/env python3
"""
Supply-Chain Scanner v2
=======================
Detects potential typosquatting and malicious packages in the Python ecosystem
by correlating GitHub push activity with PyPI metadata, scanning newly published
packages, and cross-referencing OSV known-malware advisories.

Pipeline (--mode both, default):
  Track A — GitHub repo analysis (--mode github):
    1. Download GH Archive hour snapshot, extract repos from PushEvents
    2. Fetch requirements.txt / pyproject.toml from those repos
    3. Download top-15000 PyPI packages as reference set
    4. Flag ALL packages with Levenshtein distance 1 or confusable matches
    5. Cross-reference flagged + freq==1 packages against PyPI (existence, age)
    5b. Download & scan source with weighted malware patterns, risk scoring
    5d. Check all repo-used packages against OSV MAL-* advisories

  Track B — PyPI new-package analysis (--mode pypi):
    5c. Fetch PyPI changelog of newest packages, typosquat + source scan them
    5d. Check changelog-discovered packages against OSV MAL-* advisories

  6. Print risk-stratified report

Usage:
    pip install aiohttp python-Levenshtein stdlib-list
    python scanner.py                        # full scan (both tracks)
    python scanner.py --mode github -n 100   # GitHub repo analysis only
    python scanner.py --mode pypi            # PyPI new-package analysis only
"""

from __future__ import annotations

import asyncio
import gzip
import io
import ipaddress
import json
import os
import re
import sys
import tarfile
import tomllib
import xml.etree.ElementTree as ET
import xmlrpc.client
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone

import aiohttp
import Levenshtein
import stdlib_list

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Python stdlib module names (normalized) — excluded from dep confusion candidates
_STDLIB_NAMES: set[str] = set()
for _v in stdlib_list.short_versions:
    for _name in stdlib_list.stdlib_list(_v):
        _STDLIB_NAMES.add(_name.replace(".", "_").replace("-", "_").lower())

MAX_REPOS = 10000  # default, overridden by CLI arg
CONCURRENCY = 100
TOP_PYPI_COUNT = 15000
RECENTLY_CREATED_DAYS = 7

# Thresholds for repo-used packages (higher bar — legitimate code uses eval/subprocess)
REPO_RISK_HIGH = 200
REPO_RISK_MEDIUM = 100

# Thresholds for NEW PyPI packages (lower bar — unvetted, highest value targets)
NEW_PKG_RISK_HIGH = 100
NEW_PKG_RISK_MEDIUM = 40

GH_ARCHIVE_URL = "https://data.gharchive.org/{date}-{hour}.json.gz"
RAW_GH_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
TOP_PYPI_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
)
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_RSS_NEW_URL = "https://pypi.org/rss/packages.xml"
PYPI_RSS_UPDATES_URL = "https://pypi.org/rss/updates.xml"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
PYPI_XMLRPC_URL = "https://pypi.org/pypi"

# ANSI color codes (disabled if stdout is not a TTY or --no-color)
_USE_COLOR = sys.stdout.isatty()


class C:
    """ANSI color shortcuts."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def _disable_color():
    """Set all color codes to empty strings."""
    C.RESET = C.BOLD = C.DIM = C.RED = C.YELLOW = ""
    C.GREEN = C.CYAN = C.WHITE = ""


if not _USE_COLOR:
    _disable_color()

PKG_NAME_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)")
# Captures pinned version: package==1.2.3
PINNED_VERSION_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*==\s*([^\s,;#]+)")
DIRECT_REF_RE = re.compile(r"@\s*(https?://|git\+|file://)")
MAX_SDIST_BYTES = 5 * 1024 * 1024  # 5 MB cap per package download

# ---------------------------------------------------------------------------
# Confusable character substitution pairs
# ---------------------------------------------------------------------------
CONFUSABLE_PAIRS: list[tuple[str, str]] = [
    ("l", "1"),
    ("l", "i"),
    ("1", "i"),
    ("0", "o"),
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]

# ---------------------------------------------------------------------------
# Malware-focused patterns with base weights
# ---------------------------------------------------------------------------
# Each entry: (id, compiled_regex, description, base_weight)
MALWARE_PATTERNS: list[tuple[str, re.Pattern, str, int]] = [
    (
        "cmdclass_setup",
        re.compile(r"""cmdclass\s*=\s*\{[^}]*['"](?:install|develop)['"]"""),
        "cmdclass overrides install/develop (install-time attack)",
        40,
    ),
    (
        "install_class",
        re.compile(r"class\s+\w+\s*\(\s*install\s*\)"),
        "Custom install command class",
        40,
    ),
    (
        "discord_webhook",
        re.compile(r"discord(?:app)?\.com/api/webhooks"),
        "Discord webhook C2",
        50,
    ),
    (
        "telegram_bot",
        re.compile(r"api\.telegram\.org/bot"),
        "Telegram bot C2",
        50,
    ),
    (
        "aws_secret",
        re.compile(
            r"""os\.environ\s*\[.*(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN)"""
        ),
        "AWS credential harvesting",
        30,
    ),
    (
        "base64_exec",
        re.compile(
            r"base64\.(?:b64decode|decodebytes).{0,200}(?:exec|eval)\s*\("
            r"|(?:exec|eval)\s*\(.{0,200}base64\.(?:b64decode|decodebytes)",
        ),
        "base64 decode → exec chain",
        50,
    ),
    (
        "fromhex_exec",
        re.compile(
            r"bytes\.fromhex.{0,200}(?:exec|eval)\s*\("
            r"|(?:exec|eval)\s*\(.{0,200}bytes\.fromhex",
        ),
        "hex decode → exec chain",
        40,
    ),
    (
        "reverse_exec",
        re.compile(
            r"\[::\s*-1\s*\].{0,200}(?:exec|eval)\s*\("
            r"|(?:exec|eval)\s*\(.{0,200}\[::\s*-1\s*\]",
        ),
        "Reversed string → exec chain",
        40,
    ),
    (
        "shell_cmd",
        re.compile(r"\b(?:powershell|cmd\.exe|bash\s+-c)\b"),
        "Shell command string",
        25,
    ),
    (
        "browser_data",
        re.compile(
            r"""AppData[/\\]+(?:Local|Roaming)[/\\]+(?:Google[/\\]+Chrome|Mozilla[/\\]+Firefox|BraveSoftware)"""
            r"""|\.mozilla[/\\]+firefox[/\\]+profiles"""
            r"""|Chrome[/\\]+User\s*Data[/\\]+Default[/\\]+(?:Cookies|Login\s*Data|Local\s*State|Web\s*Data)"""
            r"""|(?:Default|Profile\s*\d+)[/\\]+(?:Cookies|Login\s*Data|Local\s*State)"""
        ),
        "Browser data file access (cookie/password theft)",
        50,
    ),
    (
        "anti_vm",
        re.compile(
            r"GetModuleHandle\w*\s*\(.*SbieDll"
            r"|wmic\s+(?:bios|csproduct|computersystem)\s+get"
            r"|VBoxMouse\.sys|vmtoolsd\.exe|vboxservice\.exe|vmwaretray\.exe"
            r"|IsDebuggerPresent"
            r"|CheckRemoteDebuggerPresent"
            r"|drivers[/\\](?:vmmouse|vmhgfs|vm3dmp)\.sys"
        ),
        "Anti-VM / sandbox evasion check",
        40,
    ),
    (
        "bare_exec",
        re.compile(r"(?<!def )(?<!\.)(?<!\w)(?<!-)exec\s*\("),
        "Bare exec() call",
        20,
    ),
    (
        "bare_eval",
        re.compile(r"(?<!def )(?<!\.)(?<!\w)(?<!-)eval\s*\("),
        "Bare eval() call",
        20,
    ),
    (
        "subprocess",
        re.compile(
            r"\b(?:subprocess\.(?:run|call|Popen|check_output|check_call|getoutput)"
            r"|os\.system|os\.popen)\s*\("
        ),
        "Subprocess / os.system call",
        15,
    ),
    (
        "requests_post",
        re.compile(r"\brequests\.post\s*\("),
        "HTTP POST (potential data exfiltration)",
        15,
    ),
    (
        "credential_path",
        re.compile(
            r"""(?:open|read|copy|copyfile|Path|os\.path|expanduser|listdir|glob)\s*\(.*"""
            r"""(?:\.ssh[/\\]|\.aws[/\\]|git.credentials|\.gnupg[/\\]|\.netrc)"""
        ),
        "Credential / secret file access",
        30,
    ),
    # ── Tier 1 — strong C2/exfil signal (weight 50) ──
    (
        "exfil_webhook",
        re.compile(r"webhook\.site/"),
        "webhook.site exfiltration endpoint",
        50,
    ),
    (
        "exfil_pipedream",
        re.compile(r"(?:pipedream\.net|eo[a-z0-9]+\.m\.pipedream\.net)/"),
        "Pipedream exfil endpoint",
        50,
    ),
    (
        "exfil_requestbin",
        re.compile(r"(?:requestbin\.(?:com|net)|requestcatcher\.com)/"),
        "RequestBin data capture",
        50,
    ),
    (
        "onion_url",
        re.compile(r"\w+\.onion\b"),
        "Tor .onion domain (C2 or exfil)",
        50,
    ),
    # ── Tier 2 — strong indicator, slightly more dual-use (weight 40) ──
    (
        "ngrok_tunnel",
        re.compile(r"[a-z0-9-]+\.ngrok(?:\.io|-free\.app|\.app)/"),
        "ngrok tunnel (common C2 relay)",
        40,
    ),
    (
        "exfil_transfer",
        re.compile(r"transfer\.sh/"),
        "transfer.sh file exfiltration",
        40,
    ),
    (
        "slack_webhook",
        re.compile(r"hooks\.slack\.com/services/"),
        "Slack incoming webhook (data exfil)",
        40,
    ),
    (
        "raw_ip_url",
        re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]"),
        "Hard-coded IP URL (C2 beacon)",
        40,
    ),
    # ── Tier 3 — moderate signal (weight 30) ──
    (
        "pastebin_raw",
        re.compile(r"pastebin\.com/raw/"),
        "Pastebin raw URL (payload fetch)",
        30,
    ),
    (
        "exfil_interactsh",
        re.compile(r"[a-z0-9]+\.(?:oast\.fun|oast\.live|interactsh\.com)"),
        "Interactsh/OAST callback",
        30,
    ),
    (
        "crypto_mining",
        re.compile(r"(?:stratum\+tcp://|xmr\.|pool\.minexmr|nanopool\.org|hashvault\.pro)"),
        "Crypto mining pool connection",
        30,
    ),
    # ── Tier 4 — lower signal, context-dependent (weight 20) ──
    (
        "github_raw_exec",
        re.compile(r"raw\.githubusercontent\.com.{0,200}(?:exec|eval)\s*\("),
        "GitHub raw content → exec chain",
        20,
    ),
]

_PRIVATE_IP_RE = re.compile(r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:/]")


def _is_private_ip_url(match_text: str) -> bool:
    """Return True if the IP in a raw_ip_url match is private/reserved."""
    m = _PRIVATE_IP_RE.search(match_text)
    if not m:
        return False
    try:
        addr = ipaddress.ip_address(m.group(1))
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# File-location weight multiplier
# ---------------------------------------------------------------------------
def _file_multiplier(filename: str) -> int:
    """Return weight multiplier based on file location."""
    base = os.path.basename(filename)
    if base in ("setup.py", "setup.cfg"):
        return 3
    if base == "__init__.py":
        return 2
    return 1


def is_non_production_file(filename: str) -> bool:
    """Return True if the file is test, example, or documentation code."""
    parts = filename.replace("\\", "/").split("/")
    base = parts[-1] if parts else filename
    # Skip tests/, examples/, docs/ directories
    skip_dirs = ("tests", "test", "testing", "examples", "example", "docs", "doc", "benchmarks")
    if any(p in skip_dirs for p in parts):
        return True
    # Skip test_*.py and *_test.py
    if base.startswith("test_") or base.endswith("_test.py"):
        return True
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize(name: str) -> str:
    """PEP 503 normalize: lowercase, replace - and . with _."""
    return re.sub(r"[-.]", "_", name.strip().lower())


def parse_requirements_txt(text: str) -> tuple[set[str], dict[str, str]]:
    """Extract package names and pinned versions from a requirements.txt blob.

    Returns (names, pinned_versions) where pinned_versions maps name→version
    for entries with == specifiers.
    """
    names: set[str] = set()
    pinned: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        if DIRECT_REF_RE.search(line):
            continue
        m = PKG_NAME_RE.match(line)
        if m:
            norm = normalize(m.group(1))
            names.add(norm)
            # Check for pinned version (==X.Y.Z)
            pm = PINNED_VERSION_RE.match(line)
            if pm:
                pinned[norm] = pm.group(2).strip()
    return names, pinned


def parse_pyproject_toml(text: str) -> tuple[set[str], dict[str, str]]:
    """Extract dependency names and pinned versions from pyproject.toml.

    Returns (names, pinned_versions).
    """
    names: set[str] = set()
    pinned: dict[str, str] = {}
    try:
        data = tomllib.loads(text)
    except Exception:
        return names, pinned
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        if DIRECT_REF_RE.search(dep):
            continue
        m = PKG_NAME_RE.match(dep)
        if m:
            norm = normalize(m.group(1))
            names.add(norm)
            pm = PINNED_VERSION_RE.match(dep)
            if pm:
                pinned[norm] = pm.group(2).strip()
    return names, pinned


def detect_confusables(pkg: str, reference: str) -> bool:
    """Check if pkg matches reference after applying confusable substitutions."""
    # Try each confusable pair in both directions
    for a, b in CONFUSABLE_PAIRS:
        # Replace a→b in pkg and check against reference
        if a in pkg:
            candidate = pkg.replace(a, b)
            if candidate == reference:
                return True
        # Replace b→a in pkg and check against reference
        if b in pkg:
            candidate = pkg.replace(b, a)
            if candidate == reference:
                return True
    return False


def compute_risk_score(
    hits: list[dict],
) -> tuple[int, list[dict]]:
    """Compute risk score from pattern hits, deduplicating by (pattern, file).

    Returns (score, top_findings).
    """
    seen: set[tuple[str, str]] = set()
    unique_hits: list[dict] = []
    for h in hits:
        key = (h["pattern"], h["file"])
        if key not in seen:
            seen.add(key)
            unique_hits.append(h)

    # cmdclass/install_class are amplifiers, not standalone signals.
    # Only count them if there are other (non-cmdclass) findings present.
    _CMDCLASS_IDS = {"cmdclass_setup", "install_class"}
    has_other = any(h["pattern"] not in _CMDCLASS_IDS for h in unique_hits)

    score = 0
    for h in unique_hits:
        if h["pattern"] in _CMDCLASS_IDS and not has_other:
            continue
        score += h["weight"] * h["multiplier"]

    # Sort by weighted score descending
    unique_hits.sort(key=lambda h: -(h["weight"] * h["multiplier"]))
    return score, unique_hits


# ---------------------------------------------------------------------------
# Step 1 — Download GH Archive
# ---------------------------------------------------------------------------
async def _fetch_gh_archive_hour(
    session: aiohttp.ClientSession,
    date_str: str,
    hour: int,
) -> bytes | None:
    """Download a single GH Archive hour file, return raw gzipped bytes."""
    url = GH_ARCHIVE_URL.format(date=date_str, hour=hour)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
            if resp.status != 200:
                print(f"  WARNING: {url} returned {resp.status}, skipping")
                return None
            return await resp.read()
    except Exception as exc:
        print(f"  WARNING: {url} failed: {exc}")
        return None


def _parse_push_events(raw_gz: bytes, repos: dict[str, str], limit: int) -> int:
    """Parse PushEvents from gzipped JSON lines, add to repos dict.

    Returns number of new repos added.
    """
    data = gzip.decompress(raw_gz)
    added = 0
    for line in data.split(b"\n"):
        if not line:
            continue
        if len(repos) >= limit:
            break
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "PushEvent":
            continue
        repo_name = event.get("repo", {}).get("name")
        ref = event.get("payload", {}).get("ref", "")
        if not repo_name or not ref:
            continue
        branch = ref.removeprefix("refs/heads/")
        if repo_name not in repos:
            repos[repo_name] = branch
            added += 1
    return added


async def fetch_gh_archive(session: aiohttp.ClientSession) -> dict[str, str]:
    """Download GH Archive hour files until MAX_REPOS is reached.

    Downloads multiple hours in parallel if needed.
    """
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    date_str = yesterday.strftime("%Y-%m-%d")

    # Each hour has ~30k-50k unique repos with PushEvents
    # Estimate how many hours we need
    repos_per_hour = 35000
    hours_needed = max(1, (MAX_REPOS + repos_per_hour - 1) // repos_per_hour)
    # Pick peak hours (UTC) for maximum repo diversity
    candidate_hours = [12, 15, 18, 21, 9, 6, 0, 3, 13, 14, 16, 17, 19, 20, 22, 23, 10, 11, 7, 8, 1, 2, 4, 5]
    hours_to_fetch = candidate_hours[:hours_needed]

    print(f"\n[Step 1] Downloading GH Archive: {date_str}, {len(hours_to_fetch)} hour(s) for target {MAX_REPOS} repos")
    repos: dict[str, str] = {}

    # Download hours in batches of 4 to avoid overwhelming the server
    batch_size = 4
    for batch_start in range(0, len(hours_to_fetch), batch_size):
        if len(repos) >= MAX_REPOS:
            break
        batch_hours = hours_to_fetch[batch_start:batch_start + batch_size]
        tasks = [
            asyncio.create_task(_fetch_gh_archive_hour(session, date_str, h))
            for h in batch_hours
        ]
        results = await asyncio.gather(*tasks)
        for hour, raw in zip(batch_hours, results):
            if raw is None:
                continue
            if len(repos) >= MAX_REPOS:
                break
            added = _parse_push_events(raw, repos, MAX_REPOS)
            print(f"  Hour {hour:02d}: +{added} repos (total: {len(repos)})")

    print(f"  Found {len(repos)} unique repos from PushEvents")
    return repos


# ---------------------------------------------------------------------------
# Step 2 — Fetch dependency files
# ---------------------------------------------------------------------------
async def _fetch_file(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    repo: str,
    branch: str,
    path: str,
) -> str | None:
    url = RAW_GH_URL.format(repo=repo, branch=branch, path=path)
    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    return await r.text()
        except Exception:
            pass
    return None


async def fetch_dependencies(
    session: aiohttp.ClientSession, repos: dict[str, str]
) -> tuple[Counter[str], dict[str, set[str]], dict[str, set[str]]]:
    """Fetch requirements.txt and pyproject.toml from repos.

    Returns (freq, repo_pkgs, pkg_versions) where pkg_versions maps
    normalized package name → set of pinned versions seen across repos.
    """
    print(f"\n[Step 2] Fetching dependency files from {len(repos)} repos...")
    sem = asyncio.Semaphore(CONCURRENCY)
    freq: Counter[str] = Counter()
    repo_pkgs: dict[str, set[str]] = {}
    pkg_versions: dict[str, set[str]] = {}  # name → {version, ...}

    tasks: list[tuple[str, str, asyncio.Task]] = []
    for repo, branch in repos.items():
        for path in ("requirements.txt", "pyproject.toml"):
            t = asyncio.create_task(_fetch_file(session, sem, repo, branch, path))
            tasks.append((repo, path, t))

    results = await asyncio.gather(*(t for _, _, t in tasks), return_exceptions=True)

    for (repo, path, _), result in zip(tasks, results):
        if isinstance(result, Exception) or result is None:
            continue
        if path == "requirements.txt":
            names, pinned = parse_requirements_txt(result)
        else:
            names, pinned = parse_pyproject_toml(result)
        if names:
            repo_pkgs.setdefault(repo, set()).update(names)
            freq.update(names)
        for name, ver in pinned.items():
            pkg_versions.setdefault(name, set()).add(ver)

    repos_with_deps = len(repo_pkgs)
    unique_pkgs = len(freq)
    print(f"  Repos with dependency files: {repos_with_deps}")
    print(f"  Unique packages found: {unique_pkgs}")
    pinned_count = sum(len(v) for v in pkg_versions.values())
    print(f"  Pinned versions found: {pinned_count} across {len(pkg_versions)} packages")
    return freq, repo_pkgs, pkg_versions


# ---------------------------------------------------------------------------
# Step 3 — Top PyPI reference set
# ---------------------------------------------------------------------------
async def fetch_top_pypi(session: aiohttp.ClientSession) -> set[str]:
    """Download top-5000 PyPI packages, return normalized names."""
    print("\n[Step 3] Downloading top PyPI packages list...")
    async with session.get(TOP_PYPI_URL) as resp:
        data = await resp.json(content_type=None)

    rows = data.get("rows", [])[:TOP_PYPI_COUNT]
    names = {normalize(r["project"]) for r in rows}
    print(f"  Loaded {len(names)} top PyPI package names")
    return names


# ---------------------------------------------------------------------------
# Typosquat helpers — length-bucketed for O(n*k) instead of O(n*m)
# ---------------------------------------------------------------------------
def _build_length_buckets(names: set[str]) -> dict[int, list[str]]:
    """Group package names by length for fast neighbor lookup."""
    buckets: dict[int, list[str]] = {}
    for name in names:
        if len(name) >= 4:
            buckets.setdefault(len(name), []).append(name)
    return buckets


def _find_typosquat(
    pkg: str, top_pypi: set[str],
    _cache: dict[int, dict[int, list[str]]] | None = None,
) -> tuple[str | None, str | None]:
    """Find a typosquat match for pkg against the reference set.

    Uses length buckets to avoid iterating the full reference set.
    Returns (match, match_type) or (None, None).
    """
    # Build/cache length buckets (keyed by id of top_pypi set)
    if _cache is None:
        _cache = {}
    cache_key = id(top_pypi)
    if cache_key not in _cache:
        _cache[cache_key] = _build_length_buckets(top_pypi)
    buckets = _cache[cache_key]

    pkg_len = len(pkg)

    # Levenshtein distance 1: only check names within ±1 length
    for length in range(pkg_len - 1, pkg_len + 2):
        for ref in buckets.get(length, []):
            if Levenshtein.distance(pkg, ref) == 1:
                return ref, "levenshtein"

    # Confusable substitutions: check names within ±2 length
    for length in range(pkg_len - 2, pkg_len + 3):
        for ref in buckets.get(length, []):
            if detect_confusables(pkg, ref):
                return ref, "confusable"

    return None, None


# ---------------------------------------------------------------------------
# Step 4 — Typosquat detection (Levenshtein 1 + confusables, ALL packages)
# ---------------------------------------------------------------------------
def detect_typosquats(
    freq: Counter[str], top_pypi: set[str]
) -> list[dict]:
    """Find packages within Levenshtein distance 1 or confusable match of top PyPI."""
    print("\n[Step 4] Running typosquat detection (distance 1 + confusables)...")

    if not freq:
        print("  No packages to analyze")
        return []

    all_packages = set(freq.keys())
    flagged: list[dict] = []

    for pkg in all_packages:
        if pkg in top_pypi:
            continue
        if len(pkg) < 4:
            continue

        best_match, match_type = _find_typosquat(pkg, top_pypi)
        if best_match:
            flagged.append({
                "package": pkg,
                "similar_to": best_match,
                "match_type": match_type,
                "frequency": freq[pkg],
            })

    print(f"  Total packages checked: {len(all_packages)}")
    print(f"  Typosquat candidates: {len(flagged)}")
    return flagged


# ---------------------------------------------------------------------------
# Step 5 — PyPI cross-reference (flagged + freq==1 packages)
# ---------------------------------------------------------------------------
async def _check_pypi(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    name: str,
) -> dict:
    url = PYPI_JSON_URL.format(name=name)
    info: dict = {
        "name": name, "exists": False, "created": None,
        "summary": None, "sdist_url": None,
        "author": None, "home_page": None, "latest_version": None,
    }
    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    info["exists"] = True
                    pkg_info = data.get("info") or {}
                    info["summary"] = pkg_info.get("summary", "")
                    info["author"] = pkg_info.get("author") or pkg_info.get("maintainer") or ""
                    info["latest_version"] = pkg_info.get("version", "")
                    # Find homepage / repo URL
                    home = pkg_info.get("home_page") or ""
                    project_urls = pkg_info.get("project_urls") or {}
                    for key in ("Source", "Repository", "GitHub", "Homepage", "Source Code"):
                        if key in project_urls and project_urls[key]:
                            home = project_urls[key]
                            break
                    if not home and project_urls:
                        home = next(iter(project_urls.values()), "")
                    info["home_page"] = home
                    releases = data.get("releases", {})
                    earliest = None
                    for files in releases.values():
                        for f in files:
                            ut = f.get("upload_time")
                            if ut:
                                dt = datetime.fromisoformat(ut)
                                if earliest is None or dt < earliest:
                                    earliest = dt
                    info["created"] = earliest
                    for u in data.get("urls", []):
                        if u.get("packagetype") == "sdist":
                            info["sdist_url"] = u["url"]
                            break
                    if not info["sdist_url"]:
                        for u in data.get("urls", []):
                            if u["url"].endswith((".tar.gz", ".zip", ".whl")):
                                info["sdist_url"] = u["url"]
                                break
        except Exception:
            pass
    return info


async def pypi_cross_reference(
    session: aiohttp.ClientSession,
    freq: Counter[str],
    typosquat_flags: list[dict],
    pkg_repos: dict[str, list[str]],
    top_pypi: set[str],
) -> tuple[list[dict], list[dict], list[dict], dict[str, dict]]:
    """Check flagged + freq==1 packages against PyPI.

    Returns (typosquats, dep_confusion, recently_created, pypi_info_map).
    """
    print("\n[Step 5] Cross-referencing with PyPI...")

    if not freq:
        return [], [], [], {}

    # Packages to check: typosquat-flagged + frequency==1, minus top PyPI
    flagged_names = {f["package"] for f in typosquat_flags}
    freq1_names = {name for name, count in freq.items() if count == 1}
    to_check = (flagged_names | freq1_names) - top_pypi

    if not to_check:
        print("  No packages to cross-reference")
        return [], [], [], {}

    print(f"  Checking {len(to_check)} packages against PyPI...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = {name: asyncio.create_task(_check_pypi(session, sem, name)) for name in to_check}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    pypi_info: dict[str, dict] = {}
    for name, result in zip(tasks.keys(), results):
        if isinstance(result, dict):
            pypi_info[name] = result

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=RECENTLY_CREATED_DAYS)

    typosquats: list[dict] = []
    dep_confusion: list[dict] = []
    recently_created: list[dict] = []

    flag_lookup = {f["package"]: f for f in typosquat_flags}

    for name in to_check:
        info = pypi_info.get(name, {
            "name": name, "exists": False, "created": None,
            "summary": None, "sdist_url": None,
        })
        repos_using = pkg_repos.get(name, [])

        if name in flagged_names and info["exists"]:
            f = flag_lookup[name]
            typosquats.append({
                "package": name,
                "similar_to": f["similar_to"],
                "match_type": f["match_type"],
                "frequency": f["frequency"],
                "pypi_exists": True,
                "created": info["created"].isoformat() if info["created"] else "unknown",
                "summary": info.get("summary", ""),
                "repos": repos_using,
            })
        elif not info["exists"] and name not in _STDLIB_NAMES:
            dep_confusion.append({
                "package": name,
                "repos": repos_using,
            })

        if info["exists"] and info["created"]:
            created = info["created"]
            created_utc = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
            if created_utc > threshold:
                recently_created.append({
                    "package": name,
                    "created": info["created"].isoformat(),
                    "summary": info.get("summary", ""),
                    "repos": repos_using,
                })

    print(f"  Typosquat suspects: {len(typosquats)}")
    print(f"  Dependency confusion candidates: {len(dep_confusion)}")
    print(f"  Recently created (<{RECENTLY_CREATED_DAYS}d): {len(recently_created)}")
    return typosquats, dep_confusion, recently_created, pypi_info


# ---------------------------------------------------------------------------
# Step 5b — Source code analysis (malware-focused, weighted scoring)
# ---------------------------------------------------------------------------
# C2 patterns that should be skipped when the package itself is a client library
# Patterns that match code constructs (exec, eval, imports) — skip if in strings
_CODE_CONSTRUCT_PATTERNS = {
    "bare_exec", "bare_eval", "base64_exec", "fromhex_exec",
    "reverse_exec", "cmdclass_setup", "install_class",
    "subprocess", "requests_post",
}
_URL_PATTERNS_SKIP_IN_STRINGS = {
    "exfil_webhook", "exfil_pipedream", "exfil_requestbin",
    "onion_url", "ngrok_tunnel", "exfil_transfer",
    "slack_webhook", "pastebin_raw", "exfil_interactsh",
}
_C2_PATTERN_IDS = {
    "discord_webhook", "telegram_bot",
    "exfil_webhook", "exfil_pipedream", "exfil_requestbin",
    "onion_url", "ngrok_tunnel", "exfil_transfer",
    "slack_webhook", "raw_ip_url", "pastebin_raw",
    "exfil_interactsh", "crypto_mining", "github_raw_exec",
}
_C2_LIBRARY_KEYWORDS = {
    "telegram", "telebot", "discord", "nextcord", "disnake", "pycord",
    "slack", "slackclient", "slack_sdk",
}

# Version-reading exec/eval in setup.py — extremely common, never malware
_VERSION_EXEC_RE = re.compile(
    r"(?:exec|eval)\s*\(\s*(?:compile\s*\()?\s*(?:open|f\.read|fp\.read|handle\.read)"
    r"|(?:exec|eval)\s*\(\s*(?:compile\s*\()?\s*(?:open|Path)\s*\("
)


_TRIPLE_QUOTE_RE = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'')


def _build_string_ranges(source: str) -> list[tuple[int, int]]:
    """Find all triple-quoted string/docstring ranges in source."""
    return [(m.start(), m.end()) for m in _TRIPLE_QUOTE_RE.finditer(source)]


def _in_string(pos: int, ranges: list[tuple[int, int]], source: str) -> bool:
    """Check if a position falls inside a string literal.

    Checks triple-quoted ranges first, then falls back to counting
    quote characters on the same line for single-quoted strings.
    """
    for start, end in ranges:
        if start <= pos < end:
            return True
        if start > pos:
            break
    # Check single/double quoted strings on the same line
    line_start = source.rfind("\n", 0, pos) + 1
    before = source[line_start:pos]
    # Odd number of unescaped quotes means we're inside a string
    for q in ('"', "'"):
        count = before.count(q) - before.count(f"\\{q}")
        if count % 2 == 1:
            return True
    return False


def _scan_python_source(filename: str, source: str, pkg_name: str = "") -> list[dict]:
    """Scan a single Python source string for malware patterns with weights."""
    if is_non_production_file(filename):
        return []

    # Skip C2 URL patterns for packages that ARE telegram/discord libraries
    skip_c2 = any(kw in pkg_name for kw in _C2_LIBRARY_KEYWORDS)

    base = os.path.basename(filename)
    is_setup = base in ("setup.py", "setup.cfg")

    multiplier = _file_multiplier(filename)
    hits: list[dict] = []
    string_ranges = _build_string_ranges(source)

    for pattern_id, regex, description, base_weight in MALWARE_PATTERNS:
        if skip_c2 and pattern_id in _C2_PATTERN_IDS:
            continue
        for m in regex.finditer(source):
            # Skip matches inside comments
            line_start = source.rfind("\n", 0, m.start()) + 1
            line_text = source[line_start:m.start()]
            if "#" in line_text and line_text.lstrip().startswith("#"):
                continue

            # Skip code-construct patterns inside docstrings/strings
            # (data patterns like URLs, paths, commands are always in
            # strings so the check doesn't apply to them)
            if pattern_id in _CODE_CONSTRUCT_PATTERNS:
                if _in_string(m.start(), string_ranges, source):
                    continue

            # Skip URL-based exfil patterns inside triple-quoted strings
            # (docstrings, long_description, help text) but NOT single-line strings
            # which are typically function arguments like requests.post("https://...")
            if pattern_id in _URL_PATTERNS_SKIP_IN_STRINGS:
                in_triple = False
                for rs, re_ in string_ranges:
                    if rs <= m.start() < re_:
                        in_triple = True
                        break
                    if rs > m.start():
                        break
                if in_triple:
                    continue

            line_no = source[:m.start()].count("\n") + 1
            # Capture the full source line for context
            line_end = source.find("\n", m.end())
            if line_end == -1:
                line_end = len(source)
            context = source[line_start:line_end].strip()
            context = re.sub(r"\s+", " ", context)

            # Skip version-reading exec/eval in setup.py
            if is_setup and pattern_id in ("bare_exec", "bare_eval"):
                if _VERSION_EXEC_RE.search(context):
                    continue

            # Skip private/loopback/reserved IPs
            if pattern_id == "raw_ip_url" and _is_private_ip_url(m.group()):
                continue

            hits.append({
                "pattern": pattern_id,
                "description": description,
                "file": filename,
                "line": line_no,
                "context": context[:300],
                "weight": base_weight,
                "multiplier": multiplier,
            })
    return hits


def _extract_and_scan(archive_bytes: bytes, url: str, pkg_name: str = "") -> list[dict]:
    """Extract .py files from an archive and scan them."""
    all_hits: list[dict] = []
    try:
        if url.endswith(".tar.gz") or url.endswith(".tgz"):
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if not member.isfile() or not member.name.endswith(".py"):
                        continue
                    if member.size > 1_000_000:
                        continue
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    try:
                        source = f.read().decode("utf-8", errors="replace")
                    finally:
                        f.close()
                    short_name = member.name.split("/", 1)[-1] if "/" in member.name else member.name
                    all_hits.extend(_scan_python_source(short_name, source, pkg_name))
        elif url.endswith(".whl") or url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                for zi in zf.infolist():
                    if not zi.filename.endswith(".py"):
                        continue
                    if zi.file_size > 1_000_000:
                        continue
                    source = zf.read(zi).decode("utf-8", errors="replace")
                    short_name = zi.filename.split("/", 1)[-1] if "/" in zi.filename else zi.filename
                    all_hits.extend(_scan_python_source(short_name, source, pkg_name))
    except Exception:
        pass
    return all_hits


async def _download_and_scan(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    name: str,
    sdist_url: str,
) -> dict:
    """Download a package archive and scan its source for malware patterns."""
    result: dict = {"name": name, "url": sdist_url, "hits": [], "score": 0, "error": None}
    async with sem:
        try:
            async with session.get(
                sdist_url, timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                if r.status != 200:
                    result["error"] = f"HTTP {r.status}"
                    return result
                length = r.content_length
                if length and length > MAX_SDIST_BYTES:
                    result["error"] = "too large"
                    return result
                data = await r.read()
                if len(data) > MAX_SDIST_BYTES:
                    result["error"] = "too large"
                    return result
        except Exception as exc:
            result["error"] = str(exc)[:80]
            return result
    hits = _extract_and_scan(data, sdist_url, name)
    score, unique_hits = compute_risk_score(hits)
    result["hits"] = unique_hits
    result["score"] = score
    return result


async def check_recent_non_top_packages(
    session: aiohttp.ClientSession,
    freq: Counter[str],
    top_pypi: set[str],
    already_checked: set[str],
    pkg_repos: dict[str, list[str]],
    max_age_days: int = 30,
    scan_depth: str = "normal",
) -> dict[str, dict]:
    """Fetch PyPI metadata for freq>=2 packages not in top_pypi or already_checked.

    Returns dict[name, pypi_info] for recently created packages that have an
    sdist_url, in the same format as pypi_cross_reference's pypi_info map.
    """
    candidates = {
        name for name, count in freq.items()
        if count >= 2 and name not in top_pypi and name not in already_checked
    }
    if not candidates:
        print("\n[Step 5a'] No additional freq>=2 packages to check")
        return {}

    print(f"\n[Step 5a'] Checking {len(candidates)} freq>=2 non-top-PyPI packages...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = {name: asyncio.create_task(_check_pypi(session, sem, name)) for name in candidates}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    extra: dict[str, dict] = {}

    for name, result in zip(tasks.keys(), results):
        if isinstance(result, Exception) or not isinstance(result, dict):
            continue
        if not result.get("exists") or not result.get("sdist_url"):
            continue
        # In "wide" mode, include all non-top-pypi packages regardless of age
        if scan_depth == "wide":
            extra[name] = result
            continue
        # In "normal" mode, only include recently created packages
        created = result.get("created")
        if created is None:
            continue
        created_utc = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
        if created_utc >= cutoff:
            extra[name] = result

    print(f"  Found {len(extra)} recently created packages with source to scan")
    return extra


async def scan_package_sources(
    session: aiohttp.ClientSession,
    pypi_info: dict[str, dict],
    pkg_repos: dict[str, list[str]],
) -> list[dict]:
    """Download and scan source archives for packages with sdist URLs.

    Returns list of packages that meet MEDIUM risk threshold or above.
    """
    to_scan = {
        name: info["sdist_url"]
        for name, info in pypi_info.items()
        if info.get("exists") and info.get("sdist_url")
    }
    if not to_scan:
        print("  No packages with downloadable source to scan")
        return []

    print(f"\n[Step 5b] Downloading & scanning source for {len(to_scan)} packages...")
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = {
        name: asyncio.create_task(_download_and_scan(session, sem, name, url))
        for name, url in to_scan.items()
    }
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    flagged: list[dict] = []
    scanned = 0
    for name, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            continue
        if result.get("error"):
            continue
        scanned += 1
        score = result.get("score", 0)
        if score >= REPO_RISK_MEDIUM:
            flagged.append({
                "package": name,
                "score": score,
                "risk": "HIGH" if score >= REPO_RISK_HIGH else "MEDIUM",
                "findings": result["hits"][:10],
                "repos": pkg_repos.get(name, []),
            })

    flagged.sort(key=lambda x: -x["score"])
    high = sum(1 for f in flagged if f["risk"] == "HIGH")
    med = sum(1 for f in flagged if f["risk"] == "MEDIUM")
    print(f"  Scanned: {scanned}, HIGH risk: {high}, MEDIUM risk: {med}")
    return flagged


# ---------------------------------------------------------------------------
# Step 5c — PyPI RSS new packages feed
# ---------------------------------------------------------------------------
async def _fetch_rss(session: aiohttp.ClientSession, url: str, label: str) -> list[dict]:
    """Fetch and parse a PyPI RSS feed, return list of {name, name_raw, link, pub_date, source}."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                print(f"  WARNING: {label} RSS returned {resp.status}, skipping")
                return []
            text = await resp.text()
    except Exception as exc:
        print(f"  WARNING: {label} RSS fetch failed: {exc}")
        return []

    packages: list[dict] = []
    try:
        root = ET.fromstring(text)
        for item in root.iter("item"):
            title_el = item.find("title")
            link_el = item.find("link")
            pub_el = item.find("pubDate")
            if title_el is not None and title_el.text:
                name_raw = title_el.text.split()[0] if title_el.text else ""
                packages.append({
                    "name": normalize(name_raw),
                    "name_raw": name_raw,
                    "link": link_el.text if link_el is not None else "",
                    "pub_date": pub_el.text if pub_el is not None else "",
                    "source": label,
                })
    except ET.ParseError as exc:
        print(f"  WARNING: {label} RSS parse error: {exc}")
    return packages


async def fetch_new_pypi_packages(
    session: aiohttp.ClientSession,
) -> list[dict]:
    """Fetch both PyPI RSS feeds (new packages + recent updates)."""
    print("\n[Step 5c] Fetching PyPI RSS feeds (new packages + updates)...")

    new_task = asyncio.create_task(
        _fetch_rss(session, PYPI_RSS_NEW_URL, "new packages")
    )
    updates_task = asyncio.create_task(
        _fetch_rss(session, PYPI_RSS_UPDATES_URL, "updates")
    )
    new_pkgs, update_pkgs = await asyncio.gather(new_task, updates_task)

    # Deduplicate by normalized name, preferring new packages over updates
    seen: set[str] = set()
    combined: list[dict] = []
    for pkg in new_pkgs + update_pkgs:
        if pkg["name"] not in seen:
            seen.add(pkg["name"])
            combined.append(pkg)

    print(f"  New packages: {len(new_pkgs)}, Recent updates: {len(update_pkgs)}, Combined unique: {len(combined)}")
    return combined


async def fetch_new_pypi_via_changelog(
    session: aiohttp.ClientSession,
    hours: int = 24,
) -> list[dict]:
    """Fetch new/updated packages via PyPI XML-RPC changelog API.

    Falls back to RSS on failure.  Returns same list[dict] format as
    fetch_new_pypi_packages().
    """
    print(f"\n[Step 5c] Fetching PyPI changelog (last {hours}h) via XML-RPC...")
    try:
        loop = asyncio.get_running_loop()
        proxy = xmlrpc.client.ServerProxy(PYPI_XMLRPC_URL)

        # Run blocking XML-RPC calls in the default executor
        current_serial = await loop.run_in_executor(None, proxy.changelog_last_serial)
        # Estimate serial offset: ~50 events/sec → 180k/hour (rough upper bound)
        events_per_hour = 180_000
        since_serial = max(0, current_serial - events_per_hour * hours)

        # Paginate: changelog_since_serial returns at most 50,000 entries per
        # call.  For a 24h window the serial range can span millions of entries,
        # so we must iterate until we reach current_serial.
        BATCH_LIMIT = 50_000
        MAX_BATCHES = 200  # safety cap
        total_fetched = 0
        batch_serial = since_serial
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=hours)
        seen: dict[str, dict] = {}  # normalized name → entry dict

        for batch_num in range(1, MAX_BATCHES + 1):
            if batch_serial >= current_serial:
                break
            entries = await loop.run_in_executor(
                None, proxy.changelog_since_serial, batch_serial
            )
            if not entries:
                break
            total_fetched += len(entries)

            for entry in entries:
                # entry: (name, version, timestamp, action, serial)
                if len(entry) < 5:
                    continue
                name_raw, version, ts, action = entry[0], entry[1], entry[2], entry[3]
                if action not in ("create", "new release"):
                    continue
                event_time = datetime.fromtimestamp(ts, tz=timezone.utc)
                if event_time < cutoff:
                    continue
                norm = normalize(name_raw)
                if norm in seen:
                    continue
                seen[norm] = {
                    "name": norm,
                    "name_raw": name_raw,
                    "link": f"https://pypi.org/project/{name_raw}/",
                    "pub_date": event_time.isoformat(),
                    "source": "create" if action == "create" else "new release",
                }

            # Advance past the last serial we received
            last_serial = entries[-1][-1]  # serial is the 5th element
            if last_serial <= batch_serial:
                break  # no progress, avoid infinite loop
            batch_serial = last_serial

            if len(entries) < BATCH_LIMIT:
                break  # final (partial) batch

            if batch_num % 20 == 0:
                print(f"  ... fetched {total_fetched} entries so far ({len(seen)} packages found, batch {batch_num})")

        print(f"  XML-RPC returned {total_fetched} changelog entries over {batch_num} batch(es) (serial {since_serial}→{current_serial})")

        combined = list(seen.values())
        creates = sum(1 for p in combined if p["source"] == "create")
        releases = sum(1 for p in combined if p["source"] == "new release")
        print(f"  New creates: {creates}, New releases: {releases}, Combined unique: {len(combined)}")
        return combined

    except Exception as exc:
        print(f"  WARNING: XML-RPC changelog failed ({exc}), falling back to RSS")
        return await fetch_new_pypi_packages(session)


async def scan_new_pypi_packages(
    session: aiohttp.ClientSession,
    new_packages: list[dict],
    top_pypi: set[str],
) -> list[dict]:
    """Scan new PyPI packages for typosquatting and malicious code."""
    if not new_packages:
        return []

    print(f"\n[Step 5c'] Analyzing {len(new_packages)} new PyPI packages...")

    # Filter out top PyPI packages and run typosquat detection (CPU-only)
    candidates: list[dict] = []
    for pkg_info in new_packages:
        pkg = pkg_info["name"]
        if pkg in top_pypi:
            continue

        typosquat_match = None
        match_type = None

        if len(pkg) >= 4:
            typosquat_match, match_type = _find_typosquat(pkg, top_pypi)

        candidates.append({
            "pkg_info": pkg_info,
            "typosquat_match": typosquat_match,
            "match_type": match_type,
        })

    if not candidates:
        print("  No candidates to analyze")
        return []

    # Batch fetch all PyPI metadata in parallel
    sem = asyncio.Semaphore(CONCURRENCY)
    pypi_tasks = {
        c["pkg_info"]["name"]: asyncio.create_task(
            _check_pypi(session, sem, c["pkg_info"]["name"])
        )
        for c in candidates
    }
    pypi_results = await asyncio.gather(*pypi_tasks.values(), return_exceptions=True)
    pypi_map: dict[str, dict] = {}
    for name, result in zip(pypi_tasks.keys(), pypi_results):
        if isinstance(result, dict):
            pypi_map[name] = result

    # Determine which packages need source scanning, batch those too
    now = datetime.now(timezone.utc)
    to_scan: dict[str, str] = {}  # name → sdist_url
    for c in candidates:
        pkg = c["pkg_info"]["name"]
        pypi_data = pypi_map.get(pkg, {})
        if not pypi_data.get("sdist_url"):
            continue
        # Skip source scan for established packages in the updates/new-release feed
        if c["pkg_info"].get("source") in ("updates", "new release") and pypi_data.get("created"):
            created = pypi_data["created"]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if (now - created).days > 30:
                continue
        to_scan[pkg] = pypi_data["sdist_url"]

    scan_map: dict[str, dict] = {}
    if to_scan:
        scan_tasks = {
            name: asyncio.create_task(
                _download_and_scan(session, sem, name, url)
            )
            for name, url in to_scan.items()
        }
        scan_results = await asyncio.gather(*scan_tasks.values(), return_exceptions=True)
        for name, result in zip(scan_tasks.keys(), scan_results):
            if isinstance(result, dict) and not result.get("error"):
                scan_map[name] = result

    # Build entries and determine risk
    flagged: list[dict] = []
    STRONG_SIGNAL_WEIGHT = 30

    for c in candidates:
        pkg_info = c["pkg_info"]
        pkg = pkg_info["name"]
        typosquat_match = c["typosquat_match"]
        pypi_data = pypi_map.get(pkg, {})
        scan_result = scan_map.get(pkg, {})

        entry: dict = {
            "package": pkg,
            "name_raw": pkg_info["name_raw"],
            "link": pkg_info["link"],
            "pub_date": pkg_info["pub_date"],
            "typosquat_match": typosquat_match,
            "match_type": c["match_type"],
            "score": scan_result.get("score", 0),
            "risk": "INFO",
            "findings": scan_result.get("hits", [])[:10],
            "author": pypi_data.get("author", ""),
            "home_page": pypi_data.get("home_page", ""),
            "created": pypi_data["created"].isoformat() if pypi_data.get("created") else "",
            "summary": pypi_data.get("summary", ""),
            "latest_version": pypi_data.get("latest_version", ""),
        }

        has_strong_signal = any(
            f["weight"] >= STRONG_SIGNAL_WEIGHT for f in entry["findings"]
        )

        if has_strong_signal and entry["score"] >= NEW_PKG_RISK_HIGH:
            entry["risk"] = "HIGH"
        elif typosquat_match and has_strong_signal:
            entry["risk"] = "HIGH"
        elif entry["score"] >= NEW_PKG_RISK_HIGH:
            entry["risk"] = "MEDIUM"
        elif entry["score"] >= NEW_PKG_RISK_MEDIUM:
            entry["risk"] = "MEDIUM"
        else:
            entry["risk"] = "INFO"

        if entry["risk"] in ("HIGH", "MEDIUM"):
            flagged.append(entry)

    high = sum(1 for f in flagged if f["risk"] == "HIGH")
    med = sum(1 for f in flagged if f["risk"] == "MEDIUM")
    print(f"  Flagged: {len(flagged)} (HIGH: {high}, MEDIUM: {med})")
    return flagged


# ---------------------------------------------------------------------------
# Step 5d — OSV known malware check
# ---------------------------------------------------------------------------
async def _fetch_osv_affected_versions(
    session: aiohttp.ClientSession,
    vuln_id: str,
) -> list[str]:
    """Fetch affected versions for a specific OSV vulnerability."""
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
    except Exception:
        return []

    versions: set[str] = set()
    for affected in data.get("affected", []):
        for v in affected.get("versions", []):
            versions.add(v)
    return sorted(versions)


async def _check_version_affected(
    session: aiohttp.ClientSession,
    name: str,
    version: str,
) -> list[dict]:
    """Query OSV with a specific version to check if it's affected."""
    try:
        async with session.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": name, "ecosystem": "PyPI"}, "version": version},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
    except Exception:
        return []

    mal_vulns = []
    for v in data.get("vulns", []):
        if v.get("id", "").startswith("MAL-"):
            mal_vulns.append(v["id"])
    return mal_vulns


async def check_osv_malware(
    session: aiohttp.ClientSession,
    package_names: list[str],
    pkg_versions: dict[str, set[str]] | None = None,
) -> list[dict]:
    """Check packages against OSV database for MAL-* advisories.

    If pkg_versions is provided, also checks specific pinned versions to
    determine if the version in use is actually affected.
    """
    if not package_names:
        return []
    if pkg_versions is None:
        pkg_versions = {}

    print(f"\n[Step 5d] Checking {len(package_names)} packages against OSV database...")
    results: list[dict] = []

    # Batch up to 1000 per request
    for i in range(0, len(package_names), 1000):
        batch = package_names[i:i + 1000]
        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"}}
            for name in batch
        ]
        try:
            async with session.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    print(f"  WARNING: OSV API returned {resp.status}")
                    continue
                data = await resp.json(content_type=None)
        except Exception as exc:
            print(f"  WARNING: OSV API error: {exc}")
            continue

        osv_results = data.get("results", [])
        for name, result_entry in zip(batch, osv_results):
            vulns = result_entry.get("vulns", [])
            mal_advisories = []
            for v in vulns:
                vid = v.get("id", "")
                if vid.startswith("MAL-"):
                    mal_advisories.append({
                        "id": vid,
                        "summary": v.get("summary", ""),
                    })
            if mal_advisories:
                results.append({
                    "package": name,
                    "advisories": mal_advisories,
                })

    if not results:
        print("  No MAL-* advisories found")
        return results

    print(f"  FOUND {len(results)} packages with MAL-* advisories!")

    # Filter out packages that have been removed from PyPI (threat neutralized)
    print("  Checking which packages still exist on PyPI...")
    sem = asyncio.Semaphore(CONCURRENCY)
    pypi_checks = {
        entry["package"]: asyncio.create_task(
            _check_pypi(session, sem, entry["package"])
        )
        for entry in results
    }
    pypi_results = await asyncio.gather(*pypi_checks.values(), return_exceptions=True)
    removed = set()
    for name, result in zip(pypi_checks.keys(), pypi_results):
        if isinstance(result, Exception) or not result.get("exists"):
            removed.add(name)
    if removed:
        print(f"  Excluded {len(removed)} removed packages: {', '.join(sorted(removed))}")
        results = [r for r in results if r["package"] not in removed]

    if not results:
        print("  All MAL-* matches were removed from PyPI — no active threats")
        return results

    # For each match, fetch affected versions and check pinned versions
    print("  Fetching affected version details...")
    for entry in results:
        name = entry["package"]

        # Fetch affected versions for first advisory
        first_id = entry["advisories"][0]["id"]
        affected_versions = await _fetch_osv_affected_versions(session, first_id)
        entry["affected_versions"] = affected_versions

        # Check pinned versions from repos
        pinned = pkg_versions.get(name, set())
        entry["pinned_versions"] = sorted(pinned)

        if pinned:
            version_status: list[dict] = []
            for ver in sorted(pinned):
                mal_hits = await _check_version_affected(session, name, ver)
                version_status.append({
                    "version": ver,
                    "affected": len(mal_hits) > 0,
                    "advisories": mal_hits,
                })
            entry["version_checks"] = version_status
            affected_count = sum(1 for v in version_status if v["affected"])
            safe_count = sum(1 for v in version_status if not v["affected"])
            print(f"    {name}: {len(pinned)} pinned version(s) checked — "
                  f"{affected_count} vulnerable, {safe_count} safe")
        else:
            entry["version_checks"] = []
            print(f"    {name}: no pinned versions found in repos (cannot verify)")

    return results


# ---------------------------------------------------------------------------
# Step 6 — Risk-stratified report
# ---------------------------------------------------------------------------
def print_report(
    repos: dict[str, str],
    repo_pkgs: dict[str, set[str]],
    freq: Counter[str],
    typosquats: list[dict],
    dep_confusion: list[dict],
    recently_created: list[dict],
    source_results: list[dict],
    new_pypi_flagged: list[dict],
    osv_malware: list[dict],
    pkg_repos: dict[str, list[str]] | None = None,
    pypi_info: dict[str, dict] | None = None,
    elapsed: timedelta | None = None,
    mode: str = "both",
) -> None:
    """Print risk-stratified report to stdout and write frequency JSON."""
    if pkg_repos is None:
        pkg_repos = {}
    if pypi_info is None:
        pypi_info = {}
    sep = "=" * 72

    print(f"\n{C.DIM}{sep}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}SUPPLY-CHAIN SCANNER v2 REPORT{C.RESET}")
    print(f"{C.DIM}{sep}{C.RESET}")

    # ── Section 1: Summary ──
    print(f"\n{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}1. SCAN SUMMARY{C.RESET}")
    print(f"{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  Date (UTC)         : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}")
    print(f"  Scan mode          : {mode}")
    print(f"  Repos scanned      : {len(repos)}")
    print(f"  Repos with deps    : {len(repo_pkgs)}")
    print(f"  Unique packages    : {len(freq)}")
    total_refs = sum(freq.values())
    print(f"  Total references   : {total_refs}")
    print(f"  New PyPI packages  : {len(new_pypi_flagged)} flagged")
    print(f"  OSV MAL-* matches  : {len(osv_malware)}")

    # ── Section 2: HIGH RISK ──
    print(f"\n{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}2. HIGH RISK{C.RESET}")
    print(f"{C.DIM}{'─' * 72}{C.RESET}")

    high_items: list[str] = []
    osv_safe_items: list[str] = []

    # OSV MAL-* — split into HIGH (vulnerable/unknown) and INFO (all versions safe)
    if osv_malware:
        for m in osv_malware:
            version_checks = m.get("version_checks", [])
            all_safe = version_checks and all(not vc["affected"] for vc in version_checks)

            if all_safe:
                # All pinned versions are safe — demote to INFO
                safe_vers = [vc["version"] for vc in version_checks]
                osv_safe_items.append(
                    f"    [OSV MALWARE] {m['package']} — "
                    f"{m['advisories'][0]['id']}, but version(s) in use "
                    f"({', '.join(safe_vers)}) not affected"
                )
                continue

            lines = [f"\n  {C.BOLD}{C.RED}[OSV MALWARE]{C.RESET} {m['package']}"]
            osv_repos = pkg_repos.get(m["package"], [])
            if osv_repos:
                lines.append(f"    Used by: {', '.join(osv_repos[:5])}"
                             + (f" ...+{len(osv_repos) - 5}" if len(osv_repos) > 5 else ""))
            for adv in m["advisories"]:
                lines.append(f"    {adv['id']}: {adv['summary'][:100]}")
            # Show affected versions
            affected_vers = m.get("affected_versions", [])
            if affected_vers:
                lines.append(f"    Affected versions: {', '.join(affected_vers)}")
            # Show version check results and action
            pinned = m.get("pinned_versions", [])
            if version_checks:
                for vc in version_checks:
                    if vc["affected"]:
                        status_str = f"{C.BOLD}{C.RED}** VULNERABLE **{C.RESET}"
                    else:
                        status_str = f"{C.BOLD}{C.GREEN}** SAFE **{C.RESET}"
                    lines.append(f"    Version {vc['version']} in use: {status_str}")
                vuln_vers = [vc["version"] for vc in version_checks if vc["affected"]]
                if vuln_vers:
                    # If every checked version is vulnerable, likely fully malicious
                    all_checked_vuln = all(vc["affected"] for vc in version_checks)
                    if all_checked_vuln and len(vuln_vers) == len(version_checks):
                        lines.append(f"    {C.BOLD}{C.CYAN}>> Action: REMOVE THIS PACKAGE — "
                                     f"all known versions are malicious{C.RESET}")
                    else:
                        if affected_vers:
                            safe_hint = f" (affected: {', '.join(affected_vers)})"
                        else:
                            safe_hint = ""
                        lines.append(f"    {C.BOLD}{C.CYAN}>> Action: UPGRADE IMMEDIATELY — "
                                     f"pin to a version not in{safe_hint}{C.RESET}")
            elif pinned:
                lines.append(f"    Pinned versions: {', '.join(pinned)} (could not verify)")
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Manually verify version is not in "
                             f"affected list: {', '.join(affected_vers) if affected_vers else 'unknown'}{C.RESET}")
            else:
                lines.append("    No pinned version found in repos")
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Check installed version — affected: "
                             f"{', '.join(affected_vers) if affected_vers else 'see advisory'}{C.RESET}")
            high_items.append("\n".join(lines))

    # Source scan HIGH
    for s in source_results:
        if s["risk"] == "HIGH":
            lines = [f"\n  {C.BOLD}{C.RED}[SOURCE SCAN]{C.RESET} {s['package']}  (score: {C.RED}{s['score']}{C.RESET})"]
            pkg_meta = pypi_info.get(s["package"], {})
            if pkg_meta.get("summary"):
                lines.append(f"    Summary: {pkg_meta['summary'][:120]}")
            if pkg_meta.get("home_page"):
                lines.append(f"    Repo: {pkg_meta['home_page']}")
            if s["repos"]:
                lines.append(f"    Used by: {', '.join(s['repos'][:3])}")
            for f in s["findings"][:5]:
                w = f["weight"] * f["multiplier"]
                lines.append(f"    [{f['description']}] {f['file']}:{f['line']} (weight={w})")
                if f.get("context"):
                    lines.append(f"      {C.GREEN}> {f['context']}{C.RESET}")
            # Action based on top finding
            top_patterns = {f["pattern"] for f in s["findings"][:5]}
            if top_patterns & {"cmdclass_setup", "install_class"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Inspect setup.py before installing "
                             f"— overrides install command, code runs at pip install time{C.RESET}")
            elif top_patterns & {"discord_webhook", "telegram_bot"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Package contains C2 callback URL "
                             f"— likely exfiltrates data on import{C.RESET}")
            elif top_patterns & {"browser_data", "credential_path"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Package accesses sensitive files "
                             f"— review code for data theft{C.RESET}")
            else:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Review flagged code paths manually{C.RESET}")
            high_items.append("\n".join(lines))

    # New PyPI packages HIGH
    for n in new_pypi_flagged:
        if n["risk"] == "HIGH":
            lines = [f"\n  {C.BOLD}{C.RED}[NEW PYPI]{C.RESET} {n['name_raw']}"]
            if n.get("author"):
                lines.append(f"    Author: {n['author']}")
            if n.get("summary"):
                lines.append(f"    Summary: {n['summary'][:120]}")
            if n.get("created"):
                lines.append(f"    Created: {n['created']}")
            if n.get("home_page"):
                lines.append(f"    Repo: {n['home_page']}")
            if n["typosquat_match"]:
                lines.append(f"    Typosquat of: {n['typosquat_match']} ({n['match_type']})")
            if n["score"]:
                lines.append(f"    Malware score: {C.RED}{n['score']}{C.RESET}")
            for f in n.get("findings", [])[:5]:
                lines.append(f"    [{f['description']}] {f['file']}:{f['line']}")
                if f.get("context"):
                    lines.append(f"      {C.GREEN}> {f['context']}{C.RESET}")
            if n["link"]:
                lines.append(f"    Link: {n['link']}")
            # Action
            home = n.get("home_page", "")
            top_patterns = {f["pattern"] for f in n.get("findings", [])[:5]}
            if top_patterns & {"cmdclass_setup", "install_class"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Inspect setup.py before installing "
                             f"— overrides install command, code runs at pip install time{C.RESET}")
            elif top_patterns & {"discord_webhook", "telegram_bot"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Package contains C2 callback URL "
                             f"— likely exfiltrates data on import{C.RESET}")
            elif top_patterns & {"browser_data", "credential_path"}:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Package accesses sensitive files "
                             f"— review code for data theft{C.RESET}")
            elif n["typosquat_match"]:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Verify you intended to install "
                             f"\"{n['name_raw']}\" and not \"{n['typosquat_match']}\"{C.RESET}")
            else:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Review flagged code paths manually{C.RESET}")
            if not home:
                lines.append(f"    {C.BOLD}{C.YELLOW}>> Warning: No source repo declared{C.RESET}")
            high_items.append("\n".join(lines))

    if high_items:
        for item in high_items:
            print(item)
    else:
        print(f"  {C.DIM}{C.GREEN}None detected.{C.RESET}")

    # ── Section 3: MEDIUM RISK ──
    print(f"\n{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}3. MEDIUM RISK{C.RESET}")
    print(f"{C.DIM}{'─' * 72}{C.RESET}")

    medium_items: list[str] = []

    # Source scan MEDIUM
    for s in source_results:
        if s["risk"] == "MEDIUM":
            lines = [f"\n  {C.YELLOW}[SOURCE SCAN]{C.RESET} {s['package']}  (score: {C.YELLOW}{s['score']}{C.RESET})"]
            pkg_meta = pypi_info.get(s["package"], {})
            if pkg_meta.get("summary"):
                lines.append(f"    Summary: {pkg_meta['summary'][:120]}")
            if pkg_meta.get("home_page"):
                lines.append(f"    Repo: {pkg_meta['home_page']}")
            if s["repos"]:
                lines.append(f"    Used by: {', '.join(s['repos'][:3])}")
            for f in s["findings"][:5]:
                w = f["weight"] * f["multiplier"]
                lines.append(f"    [{f['description']}] {f['file']}:{f['line']} (weight={w})")
                if f.get("context"):
                    lines.append(f"      {C.GREEN}> {f['context']}{C.RESET}")
            lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Review flagged code paths manually{C.RESET}")
            medium_items.append("\n".join(lines))

    # New PyPI packages MEDIUM
    for n in new_pypi_flagged:
        if n["risk"] == "MEDIUM":
            lines = [f"\n  {C.YELLOW}[NEW PYPI]{C.RESET} {n['name_raw']}"]
            if n.get("author"):
                lines.append(f"    Author: {n['author']}")
            if n.get("summary"):
                lines.append(f"    Summary: {n['summary'][:120]}")
            if n.get("created"):
                lines.append(f"    Created: {n['created']}")
            if n.get("home_page"):
                lines.append(f"    Repo: {n['home_page']}")
            if n["typosquat_match"]:
                lines.append(f"    Typosquat of: {n['typosquat_match']} ({n['match_type']})")
            if n["score"]:
                lines.append(f"    Malware score: {C.YELLOW}{n['score']}{C.RESET}")
            for f in n.get("findings", [])[:3]:
                lines.append(f"    [{f['description']}] {f['file']}:{f['line']}")
                if f.get("context"):
                    lines.append(f"      {C.GREEN}> {f['context']}{C.RESET}")
            if n["link"]:
                lines.append(f"    Link: {n['link']}")
            # Action
            if n["typosquat_match"]:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Verify you intended to install "
                             f"\"{n['name_raw']}\" and not \"{n['typosquat_match']}\"{C.RESET}")
            elif not n.get("home_page"):
                lines.append(
                    f"    {C.BOLD}{C.CYAN}>> Action: No source repo declared"
                    f" — review code before use{C.RESET}"
                )
            else:
                lines.append(f"    {C.BOLD}{C.CYAN}>> Action: Review flagged code paths manually{C.RESET}")
            medium_items.append("\n".join(lines))

    if medium_items:
        for item in medium_items:
            print(item)
    else:
        print(f"  {C.DIM}{C.GREEN}None detected.{C.RESET}")

    # ── Section 4: LOW / INFO ──
    print(f"\n{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}4. LOW / INFO{C.RESET}")
    print(f"{C.DIM}{'─' * 72}{C.RESET}")

    if dep_confusion:
        # Sort by frequency (most repos using the unclaimed name first)
        sorted_deps = sorted(dep_confusion, key=lambda d: -len(d.get("repos", [])))

        print(f"  Dependency confusion candidates (not on PyPI): {len(dep_confusion)} packages")
        for d in sorted_deps:
            repos_list = d.get("repos", [])
            freq_label = f"({len(repos_list)} repos)" if len(repos_list) != 1 else "(1 repo)"
            print(f"    [UNCLAIMED] {d['package']}  {freq_label}")
            if repos_list:
                print(f"      {', '.join(repos_list)}")
    else:
        print(f"  {C.DIM}{C.GREEN}No dependency confusion candidates detected.{C.RESET}")

    # ── Section 5: Package Frequency ──
    print(f"\n{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}5. PACKAGE FREQUENCY{C.RESET}")
    print(f"{C.DIM}{'─' * 72}{C.RESET}")
    print(f"  {len(freq)} unique packages")
    if freq:
        top10 = freq.most_common(10)
        print("  Top 10:")
        for name, count in top10:
            print(f"    {name:40s} {count}")

    elapsed_str = ""
    if elapsed is not None:
        total_secs = int(elapsed.total_seconds())
        mins, secs = divmod(total_secs, 60)
        elapsed_str = f" {C.DIM}({mins}m {secs}s){C.RESET}"
    print(f"\n{C.DIM}{sep}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}END OF REPORT{C.RESET}{elapsed_str}")
    print(f"{C.DIM}{sep}{C.RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main(changelog_hours: int = 24, scan_depth: str = "normal", mode: str = "both") -> None:
    t0 = datetime.now(timezone.utc)
    timeout = aiohttp.ClientTimeout(total=600)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Top PyPI reference set — shared by both tracks
        top_pypi = await fetch_top_pypi(session)

        # ── Track A: GitHub repo analysis ──
        if mode in ("github", "both"):
            repos = await fetch_gh_archive(session)
            if not repos:
                sys.exit("No repos found. Aborting.")

            freq, repo_pkgs, pkg_versions = await fetch_dependencies(session, repos)

            # Build reverse lookup once: package → repos using it
            pkg_repos: dict[str, list[str]] = {}
            for repo, pkgs in repo_pkgs.items():
                for p in pkgs:
                    pkg_repos.setdefault(p, []).append(repo)

            # Typosquat detection (Levenshtein 1 + confusables)
            typosquat_flags = detect_typosquats(freq, top_pypi)

            # PyPI metadata check (flagged + freq==1)
            typosquats, dep_confusion, recently_created, pypi_info = (
                await pypi_cross_reference(
                    session, freq, typosquat_flags, pkg_repos, top_pypi
                )
            )

            # Expand source scan to recently-created freq>=2 packages
            if scan_depth != "narrow":
                already_checked = set(pypi_info.keys())
                recent_extra = await check_recent_non_top_packages(
                    session, freq, top_pypi, already_checked, pkg_repos,
                    scan_depth=scan_depth,
                )
                pypi_info.update(recent_extra)

            # Source scan for flagged packages
            source_results = await scan_package_sources(
                session, pypi_info, pkg_repos
            )

            # OSV malware check against repo-discovered packages
            all_pkg_names = list(freq.keys())
            osv_malware = await check_osv_malware(session, all_pkg_names, pkg_versions)
        else:
            # Initialize empty Track A results
            repos, repo_pkgs, freq, pkg_versions = {}, {}, Counter(), {}
            pkg_repos = {}
            typosquat_flags, typosquats, dep_confusion = [], [], []
            recently_created, pypi_info = [], {}
            source_results, osv_malware = [], []

        # ── Track B: PyPI new-package analysis ──
        if mode in ("pypi", "both"):
            new_packages = await fetch_new_pypi_via_changelog(session, hours=changelog_hours)
            new_pypi_flagged = await scan_new_pypi_packages(
                session, new_packages, top_pypi
            )
            # In pypi-only mode, run OSV against changelog-discovered packages
            if mode == "pypi":
                pypi_names = [p["name"] for p in new_packages]
                osv_malware = await check_osv_malware(session, pypi_names)
        else:
            new_pypi_flagged = []

    # Report — always runs, handles empty data gracefully
    elapsed = datetime.now(timezone.utc) - t0

    # Tee stdout to capture report output for file
    _real_stdout = sys.stdout
    _buf = io.StringIO()

    class _Tee:
        def write(self, s):
            _real_stdout.write(s)
            _buf.write(s)

        def flush(self):
            _real_stdout.flush()

    sys.stdout = _Tee()
    try:
        print_report(
            repos, repo_pkgs, freq, typosquats,
            dep_confusion, recently_created,
            source_results, new_pypi_flagged, osv_malware,
            pkg_repos=pkg_repos,
            pypi_info=pypi_info,
            elapsed=elapsed,
            mode=mode,
        )
    finally:
        sys.stdout = _real_stdout

    # Write plain-text report (strip ANSI codes)
    _ansi_re = re.compile(r"\033\[[0-9;]*m")
    report_path = "report-scanner.txt"
    with open(report_path, "w") as f:
        f.write(_ansi_re.sub("", _buf.getvalue()))
    print(f"\nReport written to {report_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Supply-Chain Scanner v2")
    parser.add_argument(
        "-n", "--repos", type=int, default=MAX_REPOS,
        help=f"Number of repos to scan (default: {MAX_REPOS})",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--changelog-hours", type=int, default=24,
        help="Hours of PyPI changelog to fetch (default: 24)",
    )
    parser.add_argument(
        "--scan-depth", choices=["narrow", "normal", "wide"], default="normal",
        help="narrow=freq==1+typosquats, normal=add recent freq>=2, wide=all non-top-pypi",
    )
    parser.add_argument(
        "--mode", choices=["github", "pypi", "both"], default="both",
        help="github=repo analysis only, pypi=new package analysis only, both=full scan (default)",
    )
    args = parser.parse_args()
    MAX_REPOS = args.repos
    if args.no_color:
        _disable_color()
    asyncio.run(main(changelog_hours=args.changelog_hours, scan_depth=args.scan_depth, mode=args.mode))
