<div align="center">

```
    ____  ____  ______   ____             __
   / __ \/ __ \/ ____/  / __ )____ ______/ /____  ______
  / / / / / / / / __   / __  / __ `/ ___/ //_/ / / / __ \
 / /_/ / /_/ / /_/ /  / /_/ / /_/ / /__/ ,< / /_/ / /_/ /
/_____/_____/\____/  /_____/\__,_/\___/_/|_|\__,_/ .___/
                                                /_/
```

# DDG Backup

### DuckDuckGo Password Export Tool

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-127%20passed-brightgreen.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)](htmlcov/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![SAST: semgrep](https://img.shields.io/badge/SAST-semgrep-purple.svg)](https://semgrep.dev/)

**Export your passwords saved in DuckDuckGo Android to CSV and other popular password manager formats.**

[Features](#-features) •
[Installation](#-installation) •
[Get Recovery Code](#-how-to-get-your-recovery-code) •
[Usage](#-usage) •
[Export Formats](#-export-formats)

</div>

---

## Table of Contents

- [Description](#-description)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [How to Get Your Recovery Code](#-how-to-get-your-recovery-code)
- [Usage](#-usage)
- [Export Formats](#-export-formats)
- [Technical Architecture](#-technical-architecture)
- [Security](#-security)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Changelog](#-changelog)
- [Author](#-author)
- [License](#-license)

---

## Description

**DDG Backup** is a command-line tool that allows you to export passwords saved in the DuckDuckGo Android app.

DuckDuckGo doesn't offer a native password export feature, which can be problematic if you want to:

- Migrate to another password manager
- Create a security backup of your credentials
- Audit what passwords you have saved

This tool uses the **official DuckDuckGo Recovery Code** and the sync API to securely obtain your credentials, decrypting them locally on your computer.

---

## Features

| Feature | Description |
|---------|-------------|
| **Secure** | Local decryption - your passwords never travel in plain text |
| **No Root** | Doesn't require root or special access to your Android device |
| **Multi-format** | Export to 8 different password manager formats |
| **Official** | Uses the official DuckDuckGo Recovery Code |
| **Modern Python** | Written in Python 3.11+ with static typing |
| **Fast** | Export hundreds of passwords in seconds |

### Supported Formats

- CSV (generic)
- JSON
- Bitwarden
- 1Password
- ProtonPass
- NordPass
- RoboForm
- Keeper

---

## Requirements

- **Python 3.11** or higher
- **uv** (recommended) or pip
- Your **Recovery Code** from DuckDuckGo Android

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pynacl` | ≥1.6.2 | Cryptography (libsodium) |
| `httpx` | ≥0.28.1 | Async HTTP client |
| `pydantic` | ≥2.12.5 | Data validation |
| `loguru` | ≥0.7.3 | Logging |

---

## Installation

### Option 1: With uv (Recommended)

```bash
# Clone the repository
git clone https://github.com/user/ddgo-backup.git
cd ddgo-backup

# Install dependencies with uv
uv sync

# Verify installation
uv run python -m ddgo_backup --help
```

### Option 2: With pip

```bash
# Clone the repository
git clone https://github.com/user/ddgo-backup.git
cd ddgo-backup

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install
pip install -e .

# Verify installation
ddgo-backup --help
```

### Option 3: Quick Run Script

```bash
# Create run script
cat > run.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
uv run python -m ddgo_backup "$@"
EOF
chmod +x run.sh

# Run
./run.sh
```

---

## How to Get Your Recovery Code

The Recovery Code is the master key that allows access to your synced passwords. DuckDuckGo generates it when you activate the Sync & Backup feature.

### Step 1: Open DuckDuckGo on Your Android

<table>
<tr>
<td width="50%">

1. Open the **DuckDuckGo** app on your Android phone
2. Tap the **⋮** menu (three vertical dots)
3. Select **Settings**

</td>
<td width="50%">

```
┌─────────────────────────┐
│  DuckDuckGo Browser     │
│  ─────────────────────  │
│                         │
│  [⋮] ← Tap here         │
│    │                    │
│    ├─ Bookmarks         │
│    ├─ Downloads         │
│    └─ Settings ← Here   │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Step 2: Access Sync & Backup

<table>
<tr>
<td width="50%">

4. Inside Settings, find and tap **Sync & Backup**
5. If you don't have sync enabled, enable it first

</td>
<td width="50%">

```
┌─────────────────────────┐
│  Settings               │
│  ─────────────────────  │
│                         │
│  General                │
│  Appearance             │
│  Privacy                │
│  ─────────────────────  │
│  Sync & Backup ← Here   │
│  ─────────────────────  │
│  About                  │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Step 3: Get the Recovery Code

<table>
<tr>
<td width="50%">

6. Tap **Recovery Code** or **Save Recovery PDF**
7. Your code will be displayed or a PDF will be downloaded

</td>
<td width="50%">

```
┌─────────────────────────┐
│  Sync & Backup          │
│  ─────────────────────  │
│                         │
│  Status: Synced         │
│  Devices: 2             │
│                         │
│  ─────────────────────  │
│  Recovery Code ← Here   │
│  Save Recovery PDF      │
│  ─────────────────────  │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Step 4: Copy the Code

The Recovery Code has this format (Base64-encoded JSON):

```
eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6IkVYQU1QTE
VfRkFLRV9ET19OT1RfVVNFX1RISVNfSVNfQV9ERU1P
U1RSQVRJT04iLCJ1c2VyX2lkIjoiMDAwMDAwMDAtMDAw
MC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn19
```

> **NOTE**: The PDF splits the code into multiple lines. **DDG Backup accepts the code with line breaks** - you don't need to join it manually.

---

## Usage

### Interactive Mode (Recommended)

```bash
uv run python -m ddgo_backup
```

```
============================================================
  DuckDuckGo Password Backup Tool
============================================================

To export your passwords you need your Recovery Code.
You can find it in: DDG App -> Settings -> Sync & Backup

+-------------------------------------------------------------+
|  IMPORTANT: The code from the PDF comes in MULTIPLE LINES   |
|                                                             |
|  1. Paste the ENTIRE code (can be 3-4 lines)                |
|  2. Press ENTER                                             |
|  3. Press ENTER again (empty line) to continue              |
|                                                             |
|  >>> ENTER + ENTER (empty) = CONTINUE <<<                   |
+-------------------------------------------------------------+

Recovery Code (paste then empty ENTER):
[paste your code here, can be multiple lines]
                                              ← empty ENTER

20:19:43 | INFO     | Decoding recovery code...
20:19:43 | INFO     | Deriving authentication keys...
20:19:44 | SUCCESS  | Login successful. 2 device(s) in the account.
20:19:45 | SUCCESS  | Decrypted 104 credentials successfully

[OK] Export completed: ddg_passwords_20260118_201945.csv
   Total credentials: 104
```

### Direct Mode (with code in command line)

```bash
# Export to CSV (default format)
uv run python -m ddgo_backup --code "YOUR_RECOVERY_CODE"

# Specify output file
uv run python -m ddgo_backup --code "YOUR_RECOVERY_CODE" -o my_passwords.csv

# Export to specific format
uv run python -m ddgo_backup --code "YOUR_RECOVERY_CODE" --format bitwarden

# Verbose mode (more information)
uv run python -m ddgo_backup --code "YOUR_RECOVERY_CODE" -v
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--code` | | DuckDuckGo Recovery Code | (interactive) |
| `--output` | `-o` | Output file | `ddg_passwords_TIMESTAMP.csv` |
| `--format` | `-f` | Export format | `csv` |
| `--verbose` | `-v` | Show detailed information | `false` |
| `--help` | `-h` | Show help | |

---

## Export Formats

### Generic CSV

```bash
uv run python -m ddgo_backup --format csv
```

| Column | Description |
|--------|-------------|
| `name` | Site domain |
| `url` | Site URL |
| `username` | Username |
| `password` | Password |
| `notes` | Additional notes |
| `title` | Site title |

```csv
"name","url","username","password","notes","title"
"github.com","github.com","user","password123","","GitHub"
```

---

### JSON

```bash
uv run python -m ddgo_backup --format json
```

```json
{
  "exported_at": "2026-01-18T20:30:00",
  "total_credentials": 104,
  "credentials": [
    {
      "site": "github.com",
      "username": "user",
      "password": "password123",
      "notes": null,
      "title": "GitHub"
    }
  ]
}
```

---

### Bitwarden

```bash
uv run python -m ddgo_backup --format bitwarden -o bitwarden_import.json
```

Bitwarden-compatible JSON format:

```json
{
  "encrypted": false,
  "items": [
    {
      "type": 1,
      "name": "GitHub",
      "notes": null,
      "login": {
        "uris": [{"uri": "https://github.com"}],
        "username": "user",
        "password": "password123"
      }
    }
  ]
}
```

**How to import in Bitwarden:**
1. Open Bitwarden Web Vault
2. Go to Tools → Import Data
3. Select "Bitwarden (json)"
4. Upload the generated file

---

### 1Password

```bash
uv run python -m ddgo_backup --format 1password -o 1password_import.csv
```

| Column | Description |
|--------|-------------|
| `title` | Item title |
| `website` | Full URL |
| `username` | Username |
| `password` | Password |
| `notes` | Notes |

**How to import in 1Password:**
1. Open 1Password
2. Go to File → Import → CSV
3. Select the generated file

---

### ProtonPass

```bash
uv run python -m ddgo_backup --format protonpass -o protonpass_import.csv
```

| Column | Description |
|--------|-------------|
| `name` | Item name |
| `url` | Full URL with https:// |
| `username` | Username |
| `password` | Password |
| `note` | Notes |
| `totp` | 2FA code (empty) |

**How to import in ProtonPass:**
1. Open ProtonPass
2. Go to Settings → Import
3. Select "Import from CSV"
4. Upload the generated file

---

### NordPass

```bash
uv run python -m ddgo_backup --format nordpass -o nordpass_import.csv
```

| Column | Description |
|--------|-------------|
| `name` | Item name |
| `url` | Full URL |
| `username` | Username |
| `password` | Password |
| `note` | Notes |

**How to import in NordPass:**
1. Open NordPass
2. Go to Settings → Import Items
3. Select "CSV file"
4. Upload the generated file

---

### RoboForm

```bash
uv run python -m ddgo_backup --format roboform -o roboform_import.csv
```

| Column | Description |
|--------|-------------|
| `Name` | Item name |
| `Url` | Site URL |
| `MatchUrl` | URL for matching |
| `Login` | Username |
| `Pwd` | Password |
| `Note` | Notes |

**How to import in RoboForm:**
1. Open RoboForm
2. Go to RoboForm → Import
3. Select "CSV File"
4. Upload the generated file

---

### Keeper

```bash
uv run python -m ddgo_backup --format keeper -o keeper_import.csv
```

| Column | Description |
|--------|-------------|
| `Folder` | Destination folder |
| `Title` | Item title |
| `Login` | Username |
| `Password` | Password |
| `Website Address` | Full URL |
| `Notes` | Notes |

**How to import in Keeper:**
1. Open Keeper Web Vault
2. Go to Settings → Import
3. Select "CSV File"
4. Upload the generated file

> All passwords are imported into the "DuckDuckGo Import" folder

---

## Technical Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     RECOVERY CODE (from PDF)                         │
│         eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6Ii4uLiJ9fQ==           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    1. DECODE BASE64                                  │
│   {"recovery": {"primary_key": "xxx", "user_id": "yyy"}}           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 2. DERIVE KEYS (BLAKE2b KDF)                         │
│                                                                     │
│   primary_key ──┬──► password_hash (context: "Password")           │
│                 └──► stretched_primary_key (context: "Stretchy")   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    3. LOGIN TO SYNC API                              │
│                                                                     │
│   POST https://sync.duckduckgo.com/sync/login                      │
│   Body: {user_id, hashed_password, device_id, device_name}         │
│                                                                     │
│   Response: {token, protected_encryption_key, devices[]}           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              4. DECRYPT SECRET KEY (XSalsa20-Poly1305)              │
│                                                                     │
│   protected_encryption_key + stretched_primary_key                 │
│                         │                                           │
│                         ▼                                           │
│                    secret_key (32 bytes)                           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  5. FETCH ENCRYPTED CREDENTIALS                      │
│                                                                     │
│   GET https://sync.duckduckgo.com/sync/credentials                 │
│   Header: Authorization: Bearer {token}                            │
│                                                                     │
│   Response: {credentials: [{domain, username, password, ...}]}     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│            6. DECRYPT EACH FIELD (XSalsa20-Poly1305)                │
│                                                                     │
│   For each credential:                                              │
│     domain   = decrypt(encrypted_domain, secret_key)               │
│     username = decrypt(encrypted_username, secret_key)             │
│     password = decrypt(encrypted_password, secret_key)             │
│     notes    = decrypt(encrypted_notes, secret_key)                │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      7. EXPORT TO FILE                               │
│                                                                     │
│   CSV / JSON / Bitwarden / 1Password / ProtonPass / etc.           │
└─────────────────────────────────────────────────────────────────────┘
```

### Cryptographic Algorithms

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Key derivation | BLAKE2b with salt/personal | PyNaCl |
| Symmetric encryption | XSalsa20-Poly1305 | PyNaCl |
| Nonce format | 24 bytes at the end of ciphertext | - |

### Project Structure

```
ddgo-backup/
├── src/
│   └── ddgo_backup/
│       ├── __init__.py      # Package metadata
│       ├── __main__.py      # Entry point for python -m
│       ├── main.py          # CLI with argparse
│       ├── crypto.py        # Cryptography (KDF, XSalsa20)
│       ├── api.py           # HTTP client for sync API
│       ├── models.py        # Pydantic models
│       └── exporter.py      # Exporters (CSV, JSON, etc.)
├── pyproject.toml           # Project configuration
├── README.md                # This documentation
└── run.sh                   # Quick run script
```

---

## Security

### What This Tool Does Well

| Aspect | Implementation |
|--------|----------------|
| **Local decryption** | Your passwords are decrypted on your computer, not on any server |
| **No storage** | The tool doesn't save your Recovery Code or credentials |
| **Standard cryptography** | Uses PyNaCl (libsodium bindings), the same library DuckDuckGo uses |
| **Open source** | You can audit exactly what the code does |

### Security Warnings

| Risk | Mitigation |
|------|------------|
| **The exported file contains passwords in plain text** | Delete it immediately after importing to your new manager |
| **The Recovery Code is your master key** | Don't share it with anyone. Consider regenerating it after using this tool |
| **The code is shown on screen** | Use `--code` instead of interactive mode if you're concerned |

### Best Practices

```bash
# 1. Export passwords
uv run python -m ddgo_backup -o passwords.csv

# 2. Import to new password manager
# (follow the manager's instructions)

# 3. DELETE the file immediately
rm passwords.csv

# 4. Verify it's deleted
ls -la passwords.csv  # Should show "No such file"
```

---

## Development

This section describes how to contribute to the project, run tests, and verify code quality.

### Development Requirements

```bash
# Clone the repository
git clone https://github.com/vdirienzo/ddgo-backup.git
cd ddgo-backup

# Install dependencies including dev
uv sync --all-extras
```

### Tests

The project has a complete test suite with **96% coverage**:

```
tests/
├── conftest.py                    # 15 reusable fixtures
├── integration/
│   └── test_e2e.py                # 12 E2E tests
└── unit/
    ├── test_crypto.py             # 36 tests (99% cov)
    ├── test_exporter.py           # 36 tests (100% cov)
    ├── test_api.py                # 19 tests (89% cov)
    └── test_main.py               # 24 tests (96% cov)
```

#### Running Tests

```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov=ddgo_backup --cov-report=term-missing

# Unit tests only
uv run pytest tests/unit/

# Integration tests only
uv run pytest tests/integration/

# Specific tests
uv run pytest -k "test_crypto"

# Verbose mode
uv run pytest -v
```

#### Coverage by Module

| Module | Statements | Coverage |
|--------|------------|----------|
| `crypto.py` | 104 | 99% |
| `exporter.py` | 128 | 100% |
| `api.py` | 97 | 89% |
| `main.py` | 84 | 96% |
| `models.py` | 31 | 97% |
| **Total** | **448** | **96%** |

### Code Quality

The project uses state-of-the-art tools to maintain quality:

```bash
# Linting with Ruff
uv run ruff check src/

# Formatting with Ruff
uv run ruff format src/

# Type checking with Mypy
uv run mypy src/ --ignore-missing-imports

# Verify all
uv run ruff check src/ && uv run ruff format --check src/ && uv run mypy src/
```

### Security Audit

The code has been audited with multiple security tools:

| Tool | Purpose | Result |
|------|---------|--------|
| **Bandit** | Python security linting | 0 issues |
| **Semgrep** | SAST (Static Analysis) | 0 findings |
| **Safety** | Dependency vulnerabilities | 0 CVEs |

```bash
# Run security audit
uv run bandit -r src/

# Check dependencies
uv run safety check
```

### Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | ≥8.0 | Testing framework |
| `pytest-cov` | ≥4.0 | Code coverage |
| `respx` | ≥0.20 | HTTP mocking for httpx |
| `ruff` | ≥0.1 | Linting + formatting |
| `mypy` | ≥1.0 | Type checking |
| `bandit` | ≥1.7 | Security linting |
| `safety` | ≥2.0 | Dependency audit |

### Contribution Workflow

1. **Fork** the repository
2. **Create a branch** for your feature: `git checkout -b feature/my-feature`
3. **Write tests** for your code
4. **Verify quality**: `uv run ruff check && uv run mypy src/`
5. **Run tests**: `uv run pytest`
6. **Commit** with descriptive message
7. **Push** and create a **Pull Request**

---

## Troubleshooting

### Error: "Invalid recovery code"

**Cause**: The code wasn't copied completely or has extra characters.

**Solution**:
1. Make sure to copy the ENTIRE code from the PDF
2. The code can have 3-4 lines, that's fine
3. Press ENTER on an empty line after pasting

```bash
# Try with verbose mode for more information
uv run python -m ddgo_backup -v
```

### Error: "Login error: 401"

**Cause**: Invalid credentials.

**Solution**:
1. Verify the Recovery Code is correct
2. Make sure your Sync account is active on the phone
3. Try regenerating the Recovery Code from the app

### Error: "Connection refused" or timeout

**Cause**: Network or server problem.

**Solution**:
1. Check your internet connection
2. Try again in a few minutes
3. DuckDuckGo servers may be temporarily unavailable

### Passwords appear encrypted in CSV

**Cause**: Error decrypting with the secret key.

**Solution**:
1. Verify the Recovery Code is complete
2. Try regenerating the Recovery Code from the app
3. Run with `-v` to see more error details

### I don't have Sync & Backup in my app

**Cause**: Feature not available or disabled.

**Solution**:
1. Update DuckDuckGo to the latest version
2. Sync & Backup must be manually enabled in Settings
3. You need to create or join a sync group

---

## Changelog

### [1.2.0] - 2026-01-18

#### Added
- Complete test suite with **127 tests** and **96% coverage**
  - Unit tests for crypto.py (36 tests, 99% cov)
  - Unit tests for exporter.py (36 tests, 100% cov)
  - Unit tests for api.py (19 tests, 89% cov)
  - Unit tests for main.py (24 tests, 96% cov)
  - E2E integration tests (12 tests)
- Complete security audit:
  - Ruff: linting and formatting
  - Mypy: static type checking
  - Bandit: security linting (0 issues)
  - Semgrep: SAST scanning (0 findings)
  - Safety: dependency audit (0 CVEs)
- Development section in documentation
- Badges for tests, coverage, and security tools

#### Changed
- Code formatted with Ruff
- Type hints corrected for Mypy compliance
- Removed examples with sensitive data from documentation
- Improved UI: instruction box with aligned frame (63 columns)
- Removed unnecessary technical text from user prompt

#### Security
- Triple verification that no real recovery codes are in the code
- Updated .gitignore to block exported CSV and JSON files

### [1.1.0] - 2026-01-18

#### Added
- Support for multiline codes from PDF
- Export formats: ProtonPass, NordPass, RoboForm, Keeper
- Better error handling with descriptive messages

#### Changed
- Interactive mode now accepts multiple lines (empty ENTER to finish)
- Improved Recovery Code cleaning (removes spaces, line breaks, etc.)

#### Fixed
- Error when pasting code from PDF with line breaks

### [1.0.0] - 2026-01-18

#### Added
- Initial export to CSV, JSON, Bitwarden, 1Password
- DuckDuckGo Recovery Code support
- Compatible cryptography implementation (PyNaCl)
- Interactive CLI
- Decryption of all fields (domain, username, password, notes)

---

## Author

**Homero Thompson del Lago del Terror**

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Homero Thompson del Lago del Terror

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Disclaimer

This project is **not affiliated, associated, authorized, endorsed by, or in any way officially connected with DuckDuckGo, Inc.**, or any of its subsidiaries or affiliates.

The name "DuckDuckGo" as well as related names, marks, emblems, and images are registered trademarks of their respective owners.

**Use this tool at your own risk.** The author is not responsible for any data loss, security breaches, or any other damage resulting from the use of this tool.

---

<div align="center">

**Found it useful? Give the repository a star**

</div>
