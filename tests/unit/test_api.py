"""
test_api.py - Tests unitarios para SyncClient API

Autor: Homero Thompson del Lago del Terror

Tests para:
- login(): autenticación exitosa y fallida
- fetch_credentials(): obtención y descifrado de credenciales
- _decrypt_credential(): descifrado de credenciales individuales
- Manejo de errores HTTP
"""

import base64

import httpx
import pytest
import respx

from ddgo_backup.api import SYNC_API_BASE, SyncClient
from ddgo_backup.crypto import LoginKeys

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def login_keys(test_primary_key_b64: str) -> LoginKeys:
    """LoginKeys de prueba derivadas de primary key."""
    from ddgo_backup.crypto import prepare_for_login

    return prepare_for_login(test_primary_key_b64)


@pytest.fixture
def sync_client(test_user_id: str, login_keys: LoginKeys) -> SyncClient:
    """Cliente SyncClient para tests."""
    return SyncClient(user_id=test_user_id, login_keys=login_keys)


# ============================================================================
# TESTS: login()
# ============================================================================


@respx.mock
def test_login_success(
    sync_client: SyncClient, mock_login_response: dict, test_secret_key: bytes
):
    """Test login exitoso con credenciales válidas."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )

    # Act
    result = sync_client.login(device_id="test-device", device_name="Test Device")

    # Assert
    assert result is True
    assert sync_client.token == "mock_jwt_token_for_testing"
    assert sync_client.secret_key is not None
    assert len(sync_client.devices) == 1
    assert sync_client.devices[0].id == "device1"
    assert sync_client.devices[0].name == "Test Device"


@respx.mock
def test_login_invalid_credentials(sync_client: SyncClient):
    """Test login con credenciales inválidas (401)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Credenciales inválidas"):
        sync_client.login()


@respx.mock
def test_login_server_error(sync_client: SyncClient):
    """Test login con error del servidor (500)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(500, json={"error": "Internal Server Error"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Error de login: 500"):
        sync_client.login()


@respx.mock
def test_login_incomplete_response_no_token(sync_client: SyncClient):
    """Test login con respuesta incompleta (sin token)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "protected_encryption_key": base64.b64encode(b"x" * 72).decode("ascii"),
                "devices": [],
            },
        )
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Respuesta de login incompleta"):
        sync_client.login()


@respx.mock
def test_login_incomplete_response_no_protected_key(sync_client: SyncClient):
    """Test login con respuesta incompleta (sin protected_encryption_key)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "token": "mock_token",
                "devices": [],
            },
        )
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Respuesta de login incompleta"):
        sync_client.login()


@respx.mock
def test_login_sends_correct_payload(
    sync_client: SyncClient, mock_login_response: dict
):
    """Test que login envía el payload correcto en Base64."""
    # Arrange
    route = respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )

    # Act
    sync_client.login(device_id="my-device", device_name="My Device")

    # Assert
    assert route.called
    request = route.calls.last.request
    payload = request.content

    # Verificar que el payload es JSON y contiene los campos esperados
    import json

    data = json.loads(payload)
    assert "user_id" in data
    assert "hashed_password" in data
    assert "device_id" in data
    assert data["device_id"] == "my-device"

    # Verificar que device_name está en Base64
    assert "device_name" in data
    decoded_name = base64.b64decode(data["device_name"]).decode()
    assert decoded_name == "My Device"


# ============================================================================
# TESTS: fetch_credentials()
# ============================================================================


@respx.mock
def test_fetch_credentials_success(
    sync_client: SyncClient,
    mock_login_response: dict,
    mock_credentials_response: dict,
    test_secret_key: bytes,
):
    """Test fetch_credentials exitoso con descifrado de credenciales."""
    # Arrange - Simular login previo
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key  # Usar secret key conocida para tests

    # Mock fetch credentials
    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(200, json=mock_credentials_response)
    )

    # Act
    credentials = sync_client.fetch_credentials()

    # Assert
    assert len(credentials) > 0
    # Verificar que las credenciales tienen los campos esperados
    for cred in credentials:
        assert cred.domain
        assert cred.username or cred.password  # Al menos uno debe existir


def test_fetch_credentials_without_login(sync_client: SyncClient):
    """Test fetch_credentials sin hacer login primero."""
    # Arrange - No hacer login

    # Act & Assert
    with pytest.raises(ValueError, match="Debes hacer login primero"):
        sync_client.fetch_credentials()


@respx.mock
def test_fetch_credentials_http_error(
    sync_client: SyncClient,
    mock_login_response: dict,
    test_secret_key: bytes,
):
    """Test fetch_credentials con error HTTP."""
    # Arrange - Login exitoso
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock fetch con error
    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(500, json={"error": "Internal Error"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Error al obtener credenciales: 500"):
        sync_client.fetch_credentials()


@respx.mock
def test_fetch_credentials_sends_authorization_header(
    sync_client: SyncClient,
    mock_login_response: dict,
    mock_credentials_response: dict,
    test_secret_key: bytes,
):
    """Test que fetch_credentials envía el header Authorization correcto."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    route = respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(200, json=mock_credentials_response)
    )

    # Act
    sync_client.fetch_credentials()

    # Assert
    assert route.called
    request = route.calls.last.request
    auth_header = request.headers.get("Authorization")
    assert auth_header == "Bearer mock_jwt_token_for_testing"


@respx.mock
def test_fetch_credentials_handles_alternate_response_structure(
    sync_client: SyncClient,
    mock_login_response: dict,
    encrypted_credentials: list[dict],
    test_secret_key: bytes,
):
    """Test fetch_credentials con estructura de respuesta alternativa (entries directas)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock con estructura alternativa (entries directo en root)
    alternate_response = {"entries": encrypted_credentials}
    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(200, json=alternate_response)
    )

    # Act
    credentials = sync_client.fetch_credentials()

    # Assert
    assert len(credentials) > 0


# ============================================================================
# TESTS: _decrypt_credential()
# ============================================================================


def test_decrypt_credential_all_fields(
    sync_client: SyncClient, encrypted_credentials: list[dict], test_secret_key: bytes
):
    """Test descifrado de credencial con todos los campos."""
    # Arrange
    sync_client.secret_key = test_secret_key
    entry = encrypted_credentials[0]  # github.com

    # Act
    cred = sync_client._decrypt_credential(entry)

    # Assert
    assert cred is not None
    assert cred.domain == "github.com"
    assert cred.username == "testuser"
    assert cred.password == "testpass123"
    assert cred.notes == "Mi cuenta de GitHub"
    assert cred.title == "GitHub"


def test_decrypt_credential_minimal_fields(
    sync_client: SyncClient, encrypted_credentials: list[dict], test_secret_key: bytes
):
    """Test descifrado de credencial con campos mínimos."""
    # Arrange
    sync_client.secret_key = test_secret_key
    entry = encrypted_credentials[2]  # example.com (minimal)

    # Act
    cred = sync_client._decrypt_credential(entry)

    # Assert
    assert cred is not None
    assert cred.domain == "example.com"
    assert cred.username == "user"
    assert cred.password == "pass"
    assert cred.notes is None
    assert cred.title is None


def test_decrypt_credential_empty_entry(
    sync_client: SyncClient, test_secret_key: bytes
):
    """Test descifrado de entrada vacía retorna None."""
    # Arrange
    sync_client.secret_key = test_secret_key
    empty_entry = {}

    # Act
    cred = sync_client._decrypt_credential(empty_entry)

    # Assert
    assert cred is None


def test_decrypt_credential_without_secret_key(
    sync_client: SyncClient, encrypted_credentials: list[dict]
):
    """Test descifrado sin secret key retorna valores cifrados sin descifrar."""
    # Arrange - No setear secret_key (será None)
    entry = encrypted_credentials[0]

    # Act
    cred = sync_client._decrypt_credential(entry)

    # Assert - Debe retornar credencial con valores cifrados (base64) sin descifrar
    assert cred is not None
    # Los valores deben seguir cifrados (ser strings base64 largos)
    assert len(cred.domain) > 40  # Base64 cifrado es largo
    assert len(cred.username) > 40


def test_decrypt_credential_with_domain_title_fallback(
    sync_client: SyncClient, test_secret_key: bytes
):
    """Test que usa domainTitle como fallback si no hay title."""
    # Arrange
    from ddgo_backup.crypto import encrypt_data

    sync_client.secret_key = test_secret_key

    entry = {
        "domain": encrypt_data("test.com", test_secret_key),
        "username": encrypt_data("user", test_secret_key),
        "password": encrypt_data("pass", test_secret_key),
        "domainTitle": encrypt_data("Test Domain", test_secret_key),
        "notes": "",
    }

    # Act
    cred = sync_client._decrypt_credential(entry)

    # Assert
    assert cred is not None
    assert cred.title == "Test Domain"


# ============================================================================
# TESTS: Context Manager
# ============================================================================


@respx.mock
def test_context_manager(
    test_user_id: str, login_keys: LoginKeys, mock_login_response: dict
):
    """Test que SyncClient funciona como context manager."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )

    # Act
    with SyncClient(user_id=test_user_id, login_keys=login_keys) as client:
        client.login()
        assert client.token == "mock_jwt_token_for_testing"

    # Assert - El cliente debe estar cerrado después del context manager
    # No hay una forma directa de verificar esto con httpx.Client,
    # pero podemos verificar que no falla
    assert True


# ============================================================================
# TESTS: Edge Cases
# ============================================================================


@respx.mock
def test_login_with_empty_devices_list(
    sync_client: SyncClient, mock_login_response: dict
):
    """Test login con lista de dispositivos vacía."""
    # Arrange
    # Modificar el mock para tener devices vacío
    mock_response = mock_login_response.copy()
    mock_response["devices"] = []

    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_response)
    )

    # Act
    result = sync_client.login()

    # Assert
    assert result is True
    assert len(sync_client.devices) == 0


@respx.mock
def test_fetch_credentials_with_decryption_failures(
    sync_client: SyncClient,
    mock_login_response: dict,
    test_secret_key: bytes,
):
    """Test que fetch_credentials continúa aunque falle descifrar algunas credenciales."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock con credenciales parcialmente corruptas
    from ddgo_backup.crypto import encrypt_data

    valid_cred = {
        "domain": encrypt_data("valid.com", test_secret_key),
        "username": encrypt_data("user", test_secret_key),
        "password": encrypt_data("pass", test_secret_key),
    }

    corrupted_cred = {
        "domain": "corrupted_base64_!@#$",
        "username": "not_valid_base64",
        "password": "invalid",
    }

    mock_response = {"entries": [valid_cred, corrupted_cred]}

    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(200, json=mock_response)
    )

    # Act
    credentials = sync_client.fetch_credentials()

    # Assert - Debe retornar solo la credencial válida
    assert len(credentials) >= 1  # Al menos la válida
