# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DDG Backup is a CLI tool to export passwords from DuckDuckGo Android using the official Recovery Code. It reverse-engineers DuckDuckGo's cryptography (BLAKE2b KDF + XSalsa20-Poly1305) to decrypt credentials locally.

## Commands

```bash
# Run the tool
uv run python -m ddgo_backup
uv run python -m ddgo_backup --format bitwarden -o output.json

# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=ddgo_backup --cov-report=term-missing

# Run specific test file
uv run pytest tests/unit/test_crypto.py

# Run single test
uv run pytest -k "test_encrypt_decrypt_roundtrip"

# Linting and formatting
uv run ruff check src/
uv run ruff format src/

# Type checking
uv run mypy src/

# Security audit
uv run bandit -r src/
```

## Architecture

```
Recovery Code (Base64 JSON)
    → decode_recovery_code() extracts primary_key + user_id
    → prepare_for_login() derives password_hash + stretched_primary_key via BLAKE2b KDF
    → SyncClient.login() authenticates and decrypts secret_key
    → SyncClient.fetch_credentials() gets encrypted credentials
    → decrypt_data() decrypts each field with XSalsa20-Poly1305
    → export_to_*() writes to CSV/JSON/Bitwarden/etc.
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `crypto.py` | BLAKE2b KDF (reimplements `crypto_kdf_derive_from_key`), XSalsa20-Poly1305 encryption/decryption |
| `api.py` | `SyncClient` class - HTTP client for DuckDuckGo sync API (`/sync/login`, `/sync/credentials`) |
| `exporter.py` | Export functions for 8 formats (CSV, JSON, Bitwarden, 1Password, ProtonPass, NordPass, RoboForm, Keeper) |
| `main.py` | CLI with argparse, handles multiline Recovery Code input |
| `models.py` | Pydantic models for API responses and decrypted credentials |

### Cryptographic Details

- **Nonce format**: 24 bytes at the END of ciphertext (not beginning like PyNaCl default)
- **KDF contexts**: `b"Password"` for password_hash, `b"Stretchy"` for stretched_primary_key
- **Subkey IDs**: 1 for password_hash, 2 for stretched_primary_key

## Testing

- 127 tests with 96% coverage
- Uses `respx` for mocking httpx requests
- Test fixtures in `tests/conftest.py` provide encrypted credentials for testing
- All crypto tests verify DDG-compatible format (nonce at end)

## Export Formats

All exporters follow the same signature:
```python
def export_to_FORMAT(credentials: list[DecryptedCredential], output_path: Path | str | None = None) -> Path
```
