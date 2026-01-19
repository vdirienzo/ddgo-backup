"""
test_api.py - Unit tests for SyncClient API

Author: Homero Thompson del Lago del Terror

Tests for:
- login(): successful and failed authentication
- fetch_credentials(): fetching and decrypting credentials
- _decrypt_credential(): decrypting individual credentials
- HTTP error handling
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
    """Test LoginKeys derived from primary key."""
    from ddgo_backup.crypto import prepare_for_login

    return prepare_for_login(test_primary_key_b64)


@pytest.fixture
def sync_client(test_user_id: str, login_keys: LoginKeys) -> SyncClient:
    """SyncClient for tests."""
    return SyncClient(user_id=test_user_id, login_keys=login_keys)


# ============================================================================
# TESTS: login()
# ============================================================================


@respx.mock
def test_login_success(
    sync_client: SyncClient, mock_login_response: dict, test_secret_key: bytes
):
    """Test successful login with valid credentials."""
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
    """Test login with invalid credentials (401)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Invalid credentials"):
        sync_client.login()


@respx.mock
def test_login_server_error(sync_client: SyncClient):
    """Test login with server error (500)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(500, json={"error": "Internal Server Error"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Login error: 500"):
        sync_client.login()


@respx.mock
def test_login_incomplete_response_no_token(sync_client: SyncClient):
    """Test login with incomplete response (no token)."""
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
    with pytest.raises(ValueError, match="Incomplete login response"):
        sync_client.login()


@respx.mock
def test_login_incomplete_response_no_protected_key(sync_client: SyncClient):
    """Test login with incomplete response (no protected_encryption_key)."""
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
    with pytest.raises(ValueError, match="Incomplete login response"):
        sync_client.login()


@respx.mock
def test_login_sends_correct_payload(
    sync_client: SyncClient, mock_login_response: dict
):
    """Test that login sends correct Base64-encoded payload."""
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

    # Verify payload is JSON and contains expected fields
    import json

    data = json.loads(payload)
    assert "user_id" in data
    assert "hashed_password" in data
    assert "device_id" in data
    assert data["device_id"] == "my-device"

    # Verify device_name is Base64 encoded
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
    """Test successful fetch_credentials with credential decryption."""
    # Arrange - Simulate previous login
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key  # Use known secret key for tests

    # Mock fetch credentials
    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(200, json=mock_credentials_response)
    )

    # Act
    credentials = sync_client.fetch_credentials()

    # Assert
    assert len(credentials) > 0
    # Verify credentials have expected fields
    for cred in credentials:
        assert cred.domain
        assert cred.username or cred.password  # At least one must exist


def test_fetch_credentials_without_login(sync_client: SyncClient):
    """Test fetch_credentials without logging in first."""
    # Arrange - Don't login

    # Act & Assert
    with pytest.raises(ValueError, match="You must login first"):
        sync_client.fetch_credentials()


@respx.mock
def test_fetch_credentials_http_error(
    sync_client: SyncClient,
    mock_login_response: dict,
    test_secret_key: bytes,
):
    """Test fetch_credentials with HTTP error."""
    # Arrange - Successful login
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock fetch with error
    respx.get(f"{SYNC_API_BASE}/sync/credentials").mock(
        return_value=httpx.Response(500, json={"error": "Internal Error"})
    )

    # Act & Assert
    with pytest.raises(ValueError, match="Error fetching credentials: 500"):
        sync_client.fetch_credentials()


@respx.mock
def test_fetch_credentials_sends_authorization_header(
    sync_client: SyncClient,
    mock_login_response: dict,
    mock_credentials_response: dict,
    test_secret_key: bytes,
):
    """Test that fetch_credentials sends correct Authorization header."""
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
    """Test fetch_credentials with alternate response structure (direct entries)."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock with alternate structure (entries directly in root)
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
    """Test decrypting credential with all fields."""
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
    """Test decrypting credential with minimal fields."""
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
    """Test decrypting empty entry returns None."""
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
    """Test decrypting without secret key returns encrypted values."""
    # Arrange - Don't set secret_key (will be None)
    entry = encrypted_credentials[0]

    # Act
    cred = sync_client._decrypt_credential(entry)

    # Assert - Should return credential with encrypted values (base64) not decrypted
    assert cred is not None
    # Values should still be encrypted (long base64 strings)
    assert len(cred.domain) > 40  # Encrypted base64 is long
    assert len(cred.username) > 40


def test_decrypt_credential_with_domain_title_fallback(
    sync_client: SyncClient, test_secret_key: bytes
):
    """Test that domainTitle is used as fallback if no title."""
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
    """Test that SyncClient works as context manager."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )

    # Act
    with SyncClient(user_id=test_user_id, login_keys=login_keys) as client:
        client.login()
        assert client.token == "mock_jwt_token_for_testing"

    # Assert - Client should be closed after context manager
    # There's no direct way to verify this with httpx.Client,
    # but we can verify it doesn't fail
    assert True


# ============================================================================
# TESTS: Edge Cases
# ============================================================================


@respx.mock
def test_login_with_empty_devices_list(
    sync_client: SyncClient, mock_login_response: dict
):
    """Test login with empty devices list."""
    # Arrange
    # Modify mock to have empty devices
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
    """Test that fetch_credentials continues even if some credentials fail to decrypt."""
    # Arrange
    respx.post(f"{SYNC_API_BASE}/sync/login").mock(
        return_value=httpx.Response(200, json=mock_login_response)
    )
    sync_client.login()
    sync_client.secret_key = test_secret_key

    # Mock with partially corrupted credentials
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

    # Assert - Should return only the valid credential
    assert len(credentials) >= 1  # At least the valid one
