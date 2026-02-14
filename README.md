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
- `stdlib-list`

```
pip install aiohttp python-Levenshtein stdlib-list
```

## Usage

```bash
# Default: full scan (both tracks), 10,000 repos, 24h changelog
python scanner.py

# Scan 100 repos (faster, for testing)
python scanner.py -n 100

# GitHub repo analysis only (skip PyPI changelog)
python scanner.py --mode github -n 100

# PyPI new-package analysis only (skip GH Archive)
python scanner.py --mode pypi --changelog-hours 1

# Last 6 hours of new PyPI packages
python scanner.py --mode pypi --changelog-hours 6

# Wider source scan (all non-top-PyPI packages, not just recent)
python scanner.py --scan-depth wide

# Narrow scan (only freq==1 + typosquats)
python scanner.py --scan-depth narrow -n 100

# Disable colored output
python scanner.py --no-color

# Piped output auto-disables colors
python scanner.py | less
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-n`, `--repos` | 10000 | Number of GitHub repos to scan (Track A only) |
| `--mode` | `both` | `github` = Track A only, `pypi` = Track B only, `both` = full scan |
| `--changelog-hours` | 24 | Hours of PyPI changelog to fetch (Track B only) |
| `--scan-depth` | `normal` | `narrow` = freq==1 + typosquats, `normal` = add recent freq>=2, `wide` = all non-top-PyPI |
| `--no-color` | off | Disable ANSI colored output |

## Report sections

### HIGH RISK

- **[OSV MALWARE]** — Package has a `MAL-*` advisory in OSV. Shows affected versions and whether pinned versions in use are vulnerable. Entries where all versions in use are safe are excluded.
- **[SOURCE SCAN]** — Source code scored above the HIGH threshold (200+ for repo packages, 100+ for new PyPI packages with a strong signal). Shows pattern matches with code context.
- **[NEW PYPI]** — Recently published package with high malware score or typosquat match combined with strong malware signals.

### MEDIUM RISK

- **[SOURCE SCAN]** — Source code scored above the MEDIUM threshold but below HIGH.
- **[NEW PYPI]** — New package with moderate malware score and at least one strong signal (weight >= 30), or a typosquat match with score >= 40.

### LOW / INFO

- **Dependency confusion candidates** — Package names found in repos that don't exist on PyPI. Sorted by frequency (number of repos referencing the unclaimed name).

## Malware patterns

The scanner looks for these patterns in Python source, weighted by severity:

**Tier 1 — C2 / exfiltration endpoints (weight 50):**

| Pattern | Description |
|---------|-------------|
| `discord_webhook` | Discord webhook URL |
| `telegram_bot` | Telegram bot API URL |
| `exfil_webhook` | webhook.site exfiltration endpoint |
| `exfil_pipedream` | Pipedream exfil endpoint |
| `exfil_requestbin` | RequestBin data capture |
| `onion_url` | Tor .onion domain |
| `base64_exec` | base64 decode chained to exec/eval |
| `b64_echo_decode` | `echo <base64> \| base64 -D` runtime deobfuscation |
| `curl_pipe_shell` | `curl/wget` piped to `sh/bash/zsh` |
| `browser_data` | Browser cookie/password file access |

**Tier 2 — Install-time attacks, obfuscation, tunneling (weight 40):**

| Pattern | Description |
|---------|-------------|
| `cmdclass_setup` | `cmdclass=` overrides install/develop in setup.py |
| `install_class` | Custom install command class |
| `fromhex_exec` | `bytes.fromhex` chained to exec/eval |
| `reverse_exec` | Reversed string chained to exec/eval |
| `anti_vm` | VM/sandbox detection evasion |
| `ngrok_tunnel` | ngrok tunnel (common C2 relay) |
| `exfil_transfer` | transfer.sh file exfiltration |
| `slack_webhook` | Slack incoming webhook |
| `raw_ip_url` | Hard-coded IP URL (C2 beacon) |

**Tier 3 — Credential access, suspicious URLs (weight 30):**

| Pattern | Description |
|---------|-------------|
| `aws_secret` | AWS credential harvesting via `os.environ` |
| `credential_path` | SSH/GPG/netrc/aws file access |
| `pastebin_raw` | Pastebin raw URL (payload fetch) |
| `exfil_interactsh` | Interactsh/OAST callback |
| `crypto_mining` | Crypto mining pool connection |

**Tier 4 — Shell, exec, subprocess (weight 20-25):**

| Pattern | Weight | Description |
|---------|--------|-------------|
| `shell_cmd` | 25 | Shell command strings (powershell, cmd.exe, bash -c) |
| `bare_exec` | 20 | Unqualified `exec()` call |
| `bare_eval` | 20 | Unqualified `eval()` call |
| `github_raw_exec` | 20 | GitHub raw content fetched into exec/eval |

**Tier 5 — Low-weight signals (weight 15):**

| Pattern | Description |
|---------|-------------|
| `subprocess` | `subprocess.run/Popen/call`, `os.system/popen` |
| `requests_post` | `requests.post()` call |

### Weight multipliers

Weights are multiplied by file location: **3x** in `setup.py`/`setup.cfg`, **2x** in `__init__.py`, **1x** elsewhere. Matches inside comments and test/example directories are skipped.

### Skip rules

- Code-construct patterns (`bare_exec`, `subprocess`, etc.) are skipped when they appear inside strings
- C2/URL patterns (`exfil_webhook`, `curl_pipe_shell`, etc.) are skipped inside triple-quoted strings (docstrings, help text)
- `curl_pipe_shell` and `b64_echo_decode` are skipped when the line contains detection context (`re.compile`, `forbidden`, `blocked`, etc.)
- Private/loopback IPs (127.x, 10.x, 192.168.x, etc.) are excluded from `raw_ip_url`

## Risk scoring

For **repo-sourced packages** (found in GitHub dependency files):
- HIGH: score >= 200
- MEDIUM: score >= 100

For **new PyPI packages** (from changelog):
- HIGH: score >= 100 with at least one strong signal (weight >= 30), or typosquat + strong signal
- MEDIUM: score >= 40 with at least one strong signal (weight >= 30), or typosquat + score >= 40

A "strong signal" is any pattern with base weight >= 30 (Tier 1-2). This prevents packages that only accumulate low-weight `subprocess`/`requests_post` hits from being flagged.

Typosquat matches alone are not flagged — they only matter when combined with actual malware signals.

## Output

- **Terminal** — Color-coded report (ANSI). Colors auto-disable when output is piped.
- **`report-scanner.txt`** — Plain text copy of the report, written after each run.
