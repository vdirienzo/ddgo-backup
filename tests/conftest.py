"""
conftest.py - Fixtures globales para tests

Autor: Homero Thompson del Lago del Terror
"""

import base64
import json
from typing import Any

import pytest

from ddgo_backup.crypto import encrypt_data

# ============================================================================
# FIXTURES: Recovery Code y Claves de Test
# ============================================================================


@pytest.fixture
def test_primary_key() -> bytes:
    """Primary key de 32 bytes para tests."""
    return b"test_primary_key_xxxxxxxxxxxxxxx"  # Exactamente 32 bytes


@pytest.fixture
def test_primary_key_b64(test_primary_key: bytes) -> str:
    """Primary key en Base64."""
    return base64.b64encode(test_primary_key).decode("ascii")


@pytest.fixture
def test_user_id() -> str:
    """User ID de prueba (formato UUID)."""
    return "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def test_recovery_code(test_primary_key_b64: str, test_user_id: str) -> str:
    """Recovery code válido para tests."""
    data = {
        "recovery": {
            "primary_key": test_primary_key_b64,
            "user_id": test_user_id,
        }
    }
    return base64.b64encode(json.dumps(data).encode()).decode("ascii")


@pytest.fixture
def test_recovery_code_multiline(test_recovery_code: str) -> str:
    """Recovery code con saltos de línea (como viene del PDF)."""
    # Dividir en chunks de 40 caracteres
    chunks = [
        test_recovery_code[i : i + 40] for i in range(0, len(test_recovery_code), 40)
    ]
    return "\n".join(chunks)


# ============================================================================
# FIXTURES: Secret Key para cifrado/descifrado
# ============================================================================


@pytest.fixture
def test_secret_key() -> bytes:
    """Secret key de 32 bytes para tests de cifrado."""
    return b"test_secret_key_xxxxxxxxxxxxxxxx"  # Exactamente 32 bytes


# ============================================================================
# FIXTURES: Credenciales de prueba
# ============================================================================


@pytest.fixture
def sample_credentials() -> list[dict[str, Any]]:
    """Lista de credenciales descifradas de ejemplo."""
    return [
        {
            "domain": "github.com",
            "username": "testuser",
            "password": "testpass123",
            "notes": "Mi cuenta de GitHub",
            "title": "GitHub",
        },
        {
            "domain": "google.com",
            "username": "test@gmail.com",
            "password": "googlepass456",
            "notes": "",
            "title": "Google",
        },
        {
            "domain": "example.com",
            "username": "user",
            "password": "pass",
            "notes": None,
            "title": None,
        },
    ]


@pytest.fixture
def sample_decrypted_credentials(sample_credentials: list[dict]) -> list:
    """Lista de DecryptedCredential de ejemplo."""
    from ddgo_backup.crypto import DecryptedCredential

    return [
        DecryptedCredential(
            domain=c["domain"],
            username=c["username"],
            password=c["password"],
            notes=c.get("notes"),
            title=c.get("title"),
        )
        for c in sample_credentials
    ]


@pytest.fixture
def encrypted_credentials(
    sample_credentials: list[dict], test_secret_key: bytes
) -> list[dict[str, str]]:
    """Credenciales cifradas para tests de API."""
    encrypted = []
    for cred in sample_credentials:
        encrypted.append(
            {
                "domain": encrypt_data(cred["domain"], test_secret_key),
                "username": encrypt_data(cred["username"], test_secret_key),
                "password": encrypt_data(cred["password"], test_secret_key),
                "notes": encrypt_data(cred.get("notes") or "", test_secret_key),
                "title": encrypt_data(cred.get("title") or "", test_secret_key),
            }
        )
    return encrypted


# ============================================================================
# FIXTURES: Respuestas mock de API
# ============================================================================


@pytest.fixture
def mock_login_response(
    test_secret_key: bytes, test_primary_key_b64: str
) -> dict[str, Any]:
    """Respuesta mock del endpoint /sync/login."""
    # Crear una protected_encryption_key válida cifrando el secret_key
    # con el stretched_primary_key
    import nacl.utils
    from nacl.bindings import crypto_secretbox

    from ddgo_backup.crypto import prepare_for_login

    login_keys = prepare_for_login(test_primary_key_b64)

    # Cifrar secret_key con stretched_primary_key usando XSalsa20-Poly1305
    nonce = nacl.utils.random(24)  # 24 bytes nonce
    ciphertext = crypto_secretbox(
        message=test_secret_key, nonce=nonce, key=login_keys.stretched_primary_key
    )

    # Formato: [ciphertext + MAC][nonce]
    protected_key = ciphertext + nonce
    protected_key_b64 = base64.b64encode(protected_key).decode("ascii")

    return {
        "token": "mock_jwt_token_for_testing",
        "protected_encryption_key": protected_key_b64,
        "devices": [
            {"id": "device1", "name": "Test Device", "type": "android"},
        ],
    }


@pytest.fixture
def mock_credentials_response(encrypted_credentials: list[dict]) -> dict[str, Any]:
    """Respuesta mock del endpoint /sync/credentials."""
    return {
        "credentials": {
            "entries": encrypted_credentials,
            "last_modified": "2026-01-18T00:00:00Z",
        }
    }


# ============================================================================
# FIXTURES: Archivos temporales
# ============================================================================


@pytest.fixture
def temp_output_dir(tmp_path):
    """Directorio temporal para archivos de salida."""
    return tmp_path


@pytest.fixture
def temp_csv_file(tmp_path):
    """Archivo CSV temporal."""
    return tmp_path / "test_export.csv"


@pytest.fixture
def temp_json_file(tmp_path):
    """Archivo JSON temporal."""
    return tmp_path / "test_export.json"
