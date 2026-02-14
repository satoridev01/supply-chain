# Supply-Chain Scanner

Detects malicious and suspicious packages in the Python ecosystem by correlating GitHub push activity with PyPI metadata, scanning source code for malware patterns, and cross-referencing OSV advisories.

## What it does

The scanner has two independent analysis tracks controlled by `--mode`:

**Track A — GitHub repo analysis** (`--mode github`):
1. **GH Archive** — Downloads PushEvent data to find active repositories
2. **Dependency extraction** — Fetches `requirements.txt` and `pyproject.toml` from those repos
3. **Reference set** — Downloads top 15,000 PyPI packages as a baseline
4. **Typosquat detection** — Flags packages within Levenshtein distance 1 or confusable-character matches of popular packages
5. **Cross-reference & deep analysis**
   - **5a** — Checks flagged packages against PyPI metadata (existence, age, author)
   - **5b** — Downloads and scans source archives for malware patterns with weighted risk scoring
   - **5d** — Queries the OSV database for `MAL-*` advisories on repo-used packages

**Track B — PyPI new-package analysis** (`--mode pypi`):
- **5c** — Fetches PyPI changelog for brand-new packages and scans them
- **5d** — Queries the OSV database for `MAL-*` advisories on changelog-discovered packages

**Both tracks** (`--mode both`, default) run together. The report always runs and handles empty data gracefully.

## Requirements

- Python 3.11+
- `aiohttp`
- `python-Levenshtein`

```
pip install aiohttp python-Levenshtein
```

## Usage

```bash
# Default: full scan (both tracks), 10,000 repos
python scanner.py

# Scan 100 repos (faster, for testing)
python scanner.py -n 100

# GitHub repo analysis only (skip PyPI changelog)
python scanner.py --mode github -n 100

# PyPI new-package analysis only (skip GH Archive)
python scanner.py --mode pypi --changelog-hours 1

# Disable colored output
python scanner.py --no-color

# Piped output auto-disables colors
python scanner.py | less
```

## Report sections

### HIGH RISK

- **[OSV MALWARE]** — Package has a `MAL-*` advisory in OSV. Shows affected versions and whether pinned versions in use are vulnerable. Entries where all versions in use are safe are excluded.
- **[SOURCE SCAN]** — Source code scored above the HIGH threshold (200+ for repo packages, 100+ for new PyPI packages with a strong signal). Shows pattern matches with code context.
- **[NEW PYPI]** — Recently published package with high malware score or typosquat match combined with strong malware signals.

### MEDIUM RISK

- **[SOURCE SCAN]** — Source code scored above the MEDIUM threshold but below HIGH.
- **[NEW PYPI]** — New package with moderate malware score.

### LOW / INFO

- **Dependency confusion candidates** — Package names found in repos that don't exist on PyPI. Sorted by frequency (number of repos referencing the unclaimed name).

## Malware patterns

The scanner looks for these patterns in Python source, weighted by severity:

| Weight | Pattern | Description |
|--------|---------|-------------|
| 50 | `discord_webhook`, `telegram_bot` | C2 callback URLs |
| 50 | `base64_exec` | base64 decode chained to exec/eval |
| 50 | `browser_data` | Browser cookie/password file access |
| 40 | `cmdclass_setup`, `install_class` | setup.py install-time code execution |
| 40 | `fromhex_exec`, `reverse_exec` | Obfuscated exec chains |
| 40 | `anti_vm` | VM/sandbox detection evasion |
| 30 | `aws_secret` | AWS credential harvesting |
| 30 | `credential_path` | SSH/GPG/netrc file access |
| 25 | `shell_cmd` | Shell command strings (powershell, cmd.exe, bash -c) |
| 20 | `bare_exec`, `bare_eval` | Unqualified exec()/eval() calls |
| 15 | `subprocess`, `requests_post` | Subprocess calls, HTTP POST |

Weights are multiplied by file location: **3x** in `setup.py`, **2x** in `__init__.py`, **1x** elsewhere. Matches inside comments and test/example directories are skipped.

## Risk scoring

For **repo-sourced packages** (found in GitHub dependency files):
- HIGH: score >= 200
- MEDIUM: score >= 100

For **new PyPI packages** (from RSS feed):
- HIGH: score >= 100 with at least one strong signal (weight >= 30)
- MEDIUM: score >= 40

Typosquat matches alone are not flagged — they only matter when combined with actual malware signals.

## Output

- **Terminal** — Color-coded report (ANSI). Colors auto-disable when output is piped.
- **`report-scanner.txt`** — Plain text copy of the report, written after each run.
