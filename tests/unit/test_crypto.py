"""
test_crypto.py - Unit tests for cryptographic module

Author: Homero Thompson del Lago del Terror

Tests for cryptographic functions:
- KDF derivation (BLAKE2b)
- Recovery code decoding
- Login key preparation
- Protected secret key decryption
- Data encryption/decryption
"""

import base64
import json

import pytest

from ddgo_backup.crypto import (
    HASH_SIZE,
    KDF_CONTEXT_PASSWORD,
    KDF_CONTEXT_STRETCHED,
    KDF_PERSONAL_SIZE,
    NONCE_SIZE,
    PRIMARY_KEY_SIZE,
    SECRET_KEY_SIZE,
    STRETCHED_PRIMARY_KEY_SIZE,
    SUBKEY_ID_PASSWORD_HASH,
    SUBKEY_ID_STRETCHED_PK,
    DecryptedCredential,
    LoginKeys,
    _kdf_derive_from_key,
    decode_recovery_code,
    decrypt_data,
    decrypt_protected_secret_key,
    encrypt_data,
    prepare_for_login,
)

# ============================================================================
# TESTS: _kdf_derive_from_key
# ============================================================================


def test_kdf_derive_from_key_success(test_primary_key):
    """Test successful subkey derivation with KDF."""
    # Arrange
    subkey_size = 32
    subkey_id = 1
    context = b"TestCtx"

    # Act
    result = _kdf_derive_from_key(subkey_size, subkey_id, context, test_primary_key)

    # Assert
    assert isinstance(result, bytes)
    assert len(result) == subkey_size


def test_kdf_derive_from_key_different_ids_produce_different_keys(test_primary_key):
    """Test that different subkey_id produce different keys."""
    # Arrange
    context = b"TestCtx"

    # Act
    key1 = _kdf_derive_from_key(32, 1, context, test_primary_key)
    key2 = _kdf_derive_from_key(32, 2, context, test_primary_key)

    # Assert
    assert key1 != key2


def test_kdf_derive_from_key_different_contexts_produce_different_keys(
    test_primary_key,
):
    """Test that different contexts produce different keys."""
    # Arrange
    subkey_id = 1

    # Act
    key1 = _kdf_derive_from_key(32, subkey_id, b"Context1", test_primary_key)
    key2 = _kdf_derive_from_key(32, subkey_id, b"Context2", test_primary_key)

    # Assert
    assert key1 != key2


def test_kdf_derive_from_key_deterministic(test_primary_key):
    """Test that derivation is deterministic."""
    # Arrange
    subkey_size = 32
    subkey_id = 1
    context = b"TestCtx"

    # Act
    key1 = _kdf_derive_from_key(subkey_size, subkey_id, context, test_primary_key)
    key2 = _kdf_derive_from_key(subkey_size, subkey_id, context, test_primary_key)

    # Assert
    assert key1 == key2


def test_kdf_derive_from_key_context_too_long(test_primary_key):
    """Test error when context is too long."""
    # Arrange
    context = b"x" * (KDF_PERSONAL_SIZE + 1)

    # Act & Assert
    with pytest.raises(ValueError, match="Context must be"):
        _kdf_derive_from_key(32, 1, context, test_primary_key)


def test_kdf_derive_from_key_matches_ddg_contexts(test_primary_key):
    """Test that DDG contexts produce valid keys."""
    # Arrange - Use real DDG contexts
    contexts = [KDF_CONTEXT_PASSWORD, KDF_CONTEXT_STRETCHED]

    # Act & Assert - Should not raise exceptions
    for context in contexts:
        key = _kdf_derive_from_key(32, 1, context, test_primary_key)
        assert len(key) == 32


# ============================================================================
# TESTS: decode_recovery_code
# ============================================================================


def test_decode_recovery_code_success(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test successful recovery code decoding."""
    # Act
    primary_key_b64, user_id = decode_recovery_code(test_recovery_code)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_multiline(
    test_recovery_code_multiline, test_primary_key_b64, test_user_id
):
    """Test recovery code decoding with line breaks."""
    # Act
    primary_key_b64, user_id = decode_recovery_code(test_recovery_code_multiline)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_with_whitespace(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test decoding with spaces and tabs."""
    # Arrange - Add spaces and tabs
    messy_code = f"  \t{test_recovery_code}\n\t  "

    # Act
    primary_key_b64, user_id = decode_recovery_code(messy_code)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_with_hyphens(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test decoding with hyphens (manual format)."""
    # Arrange - Add hyphens every 4 characters
    code_with_hyphens = "-".join(
        [test_recovery_code[i : i + 4] for i in range(0, len(test_recovery_code), 4)]
    )

    # Act
    primary_key_b64, user_id = decode_recovery_code(code_with_hyphens)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_alternative_format(test_primary_key_b64, test_user_id):
    """Test decoding with alternative format (no 'recovery' wrapper)."""
    # Arrange - Format without wrapper
    data = {
        "primary_key": test_primary_key_b64,
        "user_id": test_user_id,
    }
    code = base64.b64encode(json.dumps(data).encode()).decode("ascii")

    # Act
    primary_key_b64, user_id = decode_recovery_code(code)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_invalid_base64():
    """Test error with invalid Base64."""
    # Arrange
    invalid_code = "not-valid-base64!@#$%"

    # Act & Assert
    with pytest.raises(ValueError, match="Invalid recovery code"):
        decode_recovery_code(invalid_code)


def test_decode_recovery_code_invalid_json():
    """Test error with invalid JSON."""
    # Arrange - Valid Base64 but invalid JSON
    invalid_json = base64.b64encode(b"{not valid json}").decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Invalid recovery code"):
        decode_recovery_code(invalid_json)


def test_decode_recovery_code_missing_fields():
    """Test error when required fields are missing."""
    # Arrange - Valid JSON but missing expected fields
    data = {"some_field": "some_value"}
    code = base64.b64encode(json.dumps(data).encode()).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Unrecognized recovery code format"):
        decode_recovery_code(code)


# ============================================================================
# TESTS: prepare_for_login
# ============================================================================


def test_prepare_for_login_success(test_primary_key_b64, test_primary_key):
    """Test successful login key preparation."""
    # Act
    result = prepare_for_login(test_primary_key_b64)

    # Assert
    assert isinstance(result, LoginKeys)
    assert len(result.password_hash) == HASH_SIZE
    assert len(result.stretched_primary_key) == STRETCHED_PRIMARY_KEY_SIZE
    assert result.primary_key == test_primary_key


def test_prepare_for_login_derives_correct_keys(test_primary_key_b64, test_primary_key):
    """Test that derived keys are correct."""
    # Act
    result = prepare_for_login(test_primary_key_b64)

    # Assert - Verify they match manual derivation
    expected_password_hash = _kdf_derive_from_key(
        HASH_SIZE, SUBKEY_ID_PASSWORD_HASH, KDF_CONTEXT_PASSWORD, test_primary_key
    )
    expected_stretched_pk = _kdf_derive_from_key(
        STRETCHED_PRIMARY_KEY_SIZE,
        SUBKEY_ID_STRETCHED_PK,
        KDF_CONTEXT_STRETCHED,
        test_primary_key,
    )

    assert result.password_hash == expected_password_hash
    assert result.stretched_primary_key == expected_stretched_pk


def test_prepare_for_login_deterministic(test_primary_key_b64):
    """Test that preparation is deterministic."""
    # Act
    result1 = prepare_for_login(test_primary_key_b64)
    result2 = prepare_for_login(test_primary_key_b64)

    # Assert
    assert result1.password_hash == result2.password_hash
    assert result1.stretched_primary_key == result2.stretched_primary_key


def test_prepare_for_login_invalid_base64():
    """Test error with invalid Base64."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode raises generic Exception
        prepare_for_login(invalid_b64)


def test_prepare_for_login_wrong_key_size():
    """Test error when primary key has incorrect size."""
    # Arrange - 16-byte key instead of 32
    short_key = base64.b64encode(b"x" * 16).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Primary key must be 32 bytes"):
        prepare_for_login(short_key)


# ============================================================================
# TESTS: decrypt_protected_secret_key
# ============================================================================


def test_decrypt_protected_secret_key_success(test_secret_key):
    """Test successful protected secret key decryption."""
    # Arrange - Encrypt a test secret key
    from nacl.bindings import crypto_secretbox
    from nacl.utils import random

    stretched_pk = random(32)
    nonce = random(NONCE_SIZE)
    ciphertext = crypto_secretbox(test_secret_key, nonce, stretched_pk)
    # DDG format: ciphertext + nonce
    protected = ciphertext + nonce
    protected_b64 = base64.b64encode(protected).decode("ascii")

    # Act
    result = decrypt_protected_secret_key(protected_b64, stretched_pk)

    # Assert
    assert result == test_secret_key
    assert len(result) == SECRET_KEY_SIZE


def test_decrypt_protected_secret_key_wrong_key():
    """Test error when decrypting with incorrect key."""
    # Arrange
    from nacl.bindings import crypto_secretbox
    from nacl.utils import random

    secret_key = random(32)
    correct_key = random(32)
    wrong_key = random(32)
    nonce = random(NONCE_SIZE)

    ciphertext = crypto_secretbox(secret_key, nonce, correct_key)
    protected = ciphertext + nonce
    protected_b64 = base64.b64encode(protected).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Error decrypting secret key"):
        decrypt_protected_secret_key(protected_b64, wrong_key)


def test_decrypt_protected_secret_key_invalid_format():
    """Test error with invalid format (too short)."""
    # Arrange - Data too short to contain nonce
    short_data = base64.b64encode(b"x" * 10).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Error decrypting secret key"):
        decrypt_protected_secret_key(short_data, b"x" * 32)


def test_decrypt_protected_secret_key_invalid_base64():
    """Test error with invalid Base64."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"
    stretched_pk = b"x" * 32

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode raises Exception
        decrypt_protected_secret_key(invalid_b64, stretched_pk)


# ============================================================================
# TESTS: encrypt_data and decrypt_data
# ============================================================================


def test_encrypt_data_success(test_secret_key):
    """Test successful data encryption."""
    # Arrange
    plaintext = "Hello, DuckDuckGo!"

    # Act
    result = encrypt_data(plaintext, test_secret_key)

    # Assert
    assert isinstance(result, str)
    assert len(result) > 0
    # Verify it's valid Base64
    decoded = base64.b64decode(result)
    assert len(decoded) > len(plaintext)  # Includes MAC and nonce


def test_decrypt_data_success(test_secret_key):
    """Test successful data decryption."""
    # Arrange
    plaintext = "Test password 123"
    encrypted = encrypt_data(plaintext, test_secret_key)

    # Act
    result = decrypt_data(encrypted, test_secret_key)

    # Assert
    assert result == plaintext


def test_encrypt_decrypt_roundtrip(test_secret_key):
    """Test that encrypt and decrypt are inverse operations."""
    # Arrange
    test_cases = [
        "simple password",
        "contraseña con ñ y acentos",
        "emoji password 🔐🦆",
        "multi\nline\npassword",
        "password with\ttabs",
        "",  # Empty string
        " ",  # Just space
        "a" * 1000,  # Long string
    ]

    for plaintext in test_cases:
        # Act
        encrypted = encrypt_data(plaintext, test_secret_key)
        decrypted = decrypt_data(encrypted, test_secret_key)

        # Assert
        assert decrypted == plaintext, f"Failed roundtrip for: {plaintext[:50]}..."


def test_encrypt_data_different_outputs_same_input(test_secret_key):
    """Test that encrypting same text produces different outputs (random nonce)."""
    # Arrange
    plaintext = "Same text"

    # Act
    encrypted1 = encrypt_data(plaintext, test_secret_key)
    encrypted2 = encrypt_data(plaintext, test_secret_key)

    # Assert
    assert encrypted1 != encrypted2  # Different due to random nonce
    # But both decrypt to the same text
    assert decrypt_data(encrypted1, test_secret_key) == plaintext
    assert decrypt_data(encrypted2, test_secret_key) == plaintext


def test_decrypt_data_empty_string(test_secret_key):
    """Test decrypting empty string."""
    # Act
    result = decrypt_data("", test_secret_key)

    # Assert
    assert result == ""


def test_decrypt_data_wrong_key(test_secret_key):
    """Test error when decrypting with incorrect key."""
    # Arrange
    plaintext = "Secret data"
    correct_key = test_secret_key
    wrong_key = b"wrong_key_32_bytes_long_here!!"
    encrypted = encrypt_data(plaintext, correct_key)

    # Act & Assert
    with pytest.raises(ValueError, match="Error decrypting data"):
        decrypt_data(encrypted, wrong_key)


def test_decrypt_data_corrupted_ciphertext(test_secret_key):
    """Test error when decrypting corrupted data."""
    # Arrange
    plaintext = "Secret data"
    encrypted = encrypt_data(plaintext, test_secret_key)
    # Corrupt the ciphertext
    encrypted_bytes = base64.b64decode(encrypted)
    corrupted = encrypted_bytes[:-1] + b"X"  # Change last byte
    corrupted_b64 = base64.b64encode(corrupted).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Error decrypting data"):
        decrypt_data(corrupted_b64, test_secret_key)


def test_decrypt_data_invalid_base64(test_secret_key):
    """Test error with invalid Base64."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode raises Exception
        decrypt_data(invalid_b64, test_secret_key)


def test_encrypt_data_unicode_characters(test_secret_key):
    """Test encrypting Unicode characters."""
    # Arrange
    unicode_texts = [
        "中文密码",  # Chinese
        "пароль",  # Russian
        "パスワード",  # Japanese
        "كلمة السر",  # Arabic
        "🦆🔐💻",  # Emojis
    ]

    for plaintext in unicode_texts:
        # Act
        encrypted = encrypt_data(plaintext, test_secret_key)
        decrypted = decrypt_data(encrypted, test_secret_key)

        # Assert
        assert decrypted == plaintext


# ============================================================================
# TESTS: DecryptedCredential (dataclass)
# ============================================================================


def test_decrypted_credential_creation():
    """Test DecryptedCredential creation."""
    # Act
    cred = DecryptedCredential(
        domain="github.com",
        username="testuser",
        password="testpass",
        notes="Test notes",
        title="GitHub",
    )

    # Assert
    assert cred.domain == "github.com"
    assert cred.username == "testuser"
    assert cred.password == "testpass"
    assert cred.notes == "Test notes"
    assert cred.title == "GitHub"


def test_decrypted_credential_optional_fields():
    """Test DecryptedCredential with optional fields as None."""
    # Act
    cred = DecryptedCredential(
        domain="example.com",
        username="user",
        password="pass",
    )

    # Assert
    assert cred.domain == "example.com"
    assert cred.username == "user"
    assert cred.password == "pass"
    assert cred.notes is None
    assert cred.title is None


# ============================================================================
# TESTS: LoginKeys (dataclass)
# ============================================================================


def test_login_keys_creation(test_primary_key):
    """Test LoginKeys creation."""
    # Arrange
    password_hash = b"x" * 32
    stretched_pk = b"y" * 32

    # Act
    keys = LoginKeys(
        password_hash=password_hash,
        stretched_primary_key=stretched_pk,
        primary_key=test_primary_key,
    )

    # Assert
    assert keys.password_hash == password_hash
    assert keys.stretched_primary_key == stretched_pk
    assert keys.primary_key == test_primary_key


# ============================================================================
# TESTS: Constants
# ============================================================================


def test_crypto_constants():
    """Test that constants have expected values."""
    # Assert - Verify sizes according to libsodium
    assert PRIMARY_KEY_SIZE == 32
    assert SECRET_KEY_SIZE == 32
    assert HASH_SIZE == 32
    assert STRETCHED_PRIMARY_KEY_SIZE == 32
    assert NONCE_SIZE == 24
    assert KDF_PERSONAL_SIZE == 16

    # Verify KDF contexts
    assert len(KDF_CONTEXT_PASSWORD) == 8
    assert len(KDF_CONTEXT_STRETCHED) == 8
    assert KDF_CONTEXT_PASSWORD == b"Password"
    assert KDF_CONTEXT_STRETCHED == b"Stretchy"

    # Verify subkey IDs
    assert SUBKEY_ID_PASSWORD_HASH == 1
    assert SUBKEY_ID_STRETCHED_PK == 2
