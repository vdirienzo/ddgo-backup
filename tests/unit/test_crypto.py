"""
test_crypto.py - Tests unitarios para módulo criptográfico

Autor: Homero Thompson del Lago del Terror

Tests de funciones criptográficas:
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
    """Test derivación exitosa de subclave con KDF."""
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
    """Test que diferentes subkey_id producen claves diferentes."""
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
    """Test que diferentes contextos producen claves diferentes."""
    # Arrange
    subkey_id = 1

    # Act
    key1 = _kdf_derive_from_key(32, subkey_id, b"Context1", test_primary_key)
    key2 = _kdf_derive_from_key(32, subkey_id, b"Context2", test_primary_key)

    # Assert
    assert key1 != key2


def test_kdf_derive_from_key_deterministic(test_primary_key):
    """Test que la derivación es determinística."""
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
    """Test error cuando el contexto es demasiado largo."""
    # Arrange
    context = b"x" * (KDF_PERSONAL_SIZE + 1)

    # Act & Assert
    with pytest.raises(ValueError, match="Context debe ser"):
        _kdf_derive_from_key(32, 1, context, test_primary_key)


def test_kdf_derive_from_key_matches_ddg_contexts(test_primary_key):
    """Test que los contextos de DDG producen claves válidas."""
    # Arrange - Usar contextos reales de DDG
    contexts = [KDF_CONTEXT_PASSWORD, KDF_CONTEXT_STRETCHED]

    # Act & Assert - No debe lanzar excepciones
    for context in contexts:
        key = _kdf_derive_from_key(32, 1, context, test_primary_key)
        assert len(key) == 32


# ============================================================================
# TESTS: decode_recovery_code
# ============================================================================


def test_decode_recovery_code_success(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test decodificación exitosa de recovery code."""
    # Act
    primary_key_b64, user_id = decode_recovery_code(test_recovery_code)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_multiline(
    test_recovery_code_multiline, test_primary_key_b64, test_user_id
):
    """Test decodificación de recovery code con saltos de línea."""
    # Act
    primary_key_b64, user_id = decode_recovery_code(test_recovery_code_multiline)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_with_whitespace(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test decodificación con espacios y tabs."""
    # Arrange - Agregar espacios y tabs
    messy_code = f"  \t{test_recovery_code}\n\t  "

    # Act
    primary_key_b64, user_id = decode_recovery_code(messy_code)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_with_hyphens(
    test_recovery_code, test_primary_key_b64, test_user_id
):
    """Test decodificación con guiones (formato manual)."""
    # Arrange - Agregar guiones cada 4 caracteres
    code_with_hyphens = "-".join(
        [test_recovery_code[i : i + 4] for i in range(0, len(test_recovery_code), 4)]
    )

    # Act
    primary_key_b64, user_id = decode_recovery_code(code_with_hyphens)

    # Assert
    assert primary_key_b64 == test_primary_key_b64
    assert user_id == test_user_id


def test_decode_recovery_code_alternative_format(test_primary_key_b64, test_user_id):
    """Test decodificación con formato alternativo (sin 'recovery' wrapper)."""
    # Arrange - Formato sin wrapper
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
    """Test error con Base64 inválido."""
    # Arrange
    invalid_code = "not-valid-base64!@#$%"

    # Act & Assert
    with pytest.raises(ValueError, match="Recovery code inválido"):
        decode_recovery_code(invalid_code)


def test_decode_recovery_code_invalid_json():
    """Test error con JSON inválido."""
    # Arrange - Base64 válido pero JSON inválido
    invalid_json = base64.b64encode(b"{not valid json}").decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Recovery code inválido"):
        decode_recovery_code(invalid_json)


def test_decode_recovery_code_missing_fields():
    """Test error cuando faltan campos requeridos."""
    # Arrange - JSON válido pero sin campos esperados
    data = {"some_field": "some_value"}
    code = base64.b64encode(json.dumps(data).encode()).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Formato de recovery code no reconocido"):
        decode_recovery_code(code)


# ============================================================================
# TESTS: prepare_for_login
# ============================================================================


def test_prepare_for_login_success(test_primary_key_b64, test_primary_key):
    """Test preparación exitosa de claves para login."""
    # Act
    result = prepare_for_login(test_primary_key_b64)

    # Assert
    assert isinstance(result, LoginKeys)
    assert len(result.password_hash) == HASH_SIZE
    assert len(result.stretched_primary_key) == STRETCHED_PRIMARY_KEY_SIZE
    assert result.primary_key == test_primary_key


def test_prepare_for_login_derives_correct_keys(test_primary_key_b64, test_primary_key):
    """Test que las claves derivadas son correctas."""
    # Act
    result = prepare_for_login(test_primary_key_b64)

    # Assert - Verificar que coinciden con derivación manual
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
    """Test que la preparación es determinística."""
    # Act
    result1 = prepare_for_login(test_primary_key_b64)
    result2 = prepare_for_login(test_primary_key_b64)

    # Assert
    assert result1.password_hash == result2.password_hash
    assert result1.stretched_primary_key == result2.stretched_primary_key


def test_prepare_for_login_invalid_base64():
    """Test error con Base64 inválido."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode lanza Exception genérico
        prepare_for_login(invalid_b64)


def test_prepare_for_login_wrong_key_size():
    """Test error cuando la primary key tiene tamaño incorrecto."""
    # Arrange - Key de 16 bytes en lugar de 32
    short_key = base64.b64encode(b"x" * 16).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Primary key debe ser 32 bytes"):
        prepare_for_login(short_key)


# ============================================================================
# TESTS: decrypt_protected_secret_key
# ============================================================================


def test_decrypt_protected_secret_key_success(test_secret_key):
    """Test descifrado exitoso de secret key protegida."""
    # Arrange - Cifrar una secret key de prueba
    from nacl.bindings import crypto_secretbox
    from nacl.utils import random

    stretched_pk = random(32)
    nonce = random(NONCE_SIZE)
    ciphertext = crypto_secretbox(test_secret_key, nonce, stretched_pk)
    # Formato DDG: ciphertext + nonce
    protected = ciphertext + nonce
    protected_b64 = base64.b64encode(protected).decode("ascii")

    # Act
    result = decrypt_protected_secret_key(protected_b64, stretched_pk)

    # Assert
    assert result == test_secret_key
    assert len(result) == SECRET_KEY_SIZE


def test_decrypt_protected_secret_key_wrong_key():
    """Test error al descifrar con clave incorrecta."""
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
    with pytest.raises(ValueError, match="Error al descifrar secret key"):
        decrypt_protected_secret_key(protected_b64, wrong_key)


def test_decrypt_protected_secret_key_invalid_format():
    """Test error con formato inválido (muy corto)."""
    # Arrange - Datos demasiado cortos para contener nonce
    short_data = base64.b64encode(b"x" * 10).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Error al descifrar secret key"):
        decrypt_protected_secret_key(short_data, b"x" * 32)


def test_decrypt_protected_secret_key_invalid_base64():
    """Test error con Base64 inválido."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"
    stretched_pk = b"x" * 32

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode lanza Exception
        decrypt_protected_secret_key(invalid_b64, stretched_pk)


# ============================================================================
# TESTS: encrypt_data y decrypt_data
# ============================================================================


def test_encrypt_data_success(test_secret_key):
    """Test cifrado exitoso de datos."""
    # Arrange
    plaintext = "Hello, DuckDuckGo!"

    # Act
    result = encrypt_data(plaintext, test_secret_key)

    # Assert
    assert isinstance(result, str)
    assert len(result) > 0
    # Verificar que es Base64 válido
    decoded = base64.b64decode(result)
    assert len(decoded) > len(plaintext)  # Incluye MAC y nonce


def test_decrypt_data_success(test_secret_key):
    """Test descifrado exitoso de datos."""
    # Arrange
    plaintext = "Test password 123"
    encrypted = encrypt_data(plaintext, test_secret_key)

    # Act
    result = decrypt_data(encrypted, test_secret_key)

    # Assert
    assert result == plaintext


def test_encrypt_decrypt_roundtrip(test_secret_key):
    """Test que encrypt y decrypt son operaciones inversas."""
    # Arrange
    test_cases = [
        "simple password",
        "contraseña con ñ y acentos",
        "emoji password 🔐🦆",
        "multi\nline\npassword",
        "password with\ttabs",
        "",  # String vacío
        " ",  # Solo espacio
        "a" * 1000,  # String largo
    ]

    for plaintext in test_cases:
        # Act
        encrypted = encrypt_data(plaintext, test_secret_key)
        decrypted = decrypt_data(encrypted, test_secret_key)

        # Assert
        assert decrypted == plaintext, f"Failed roundtrip for: {plaintext[:50]}..."


def test_encrypt_data_different_outputs_same_input(test_secret_key):
    """Test que cifrar el mismo texto produce outputs diferentes (por nonce aleatorio)."""
    # Arrange
    plaintext = "Same text"

    # Act
    encrypted1 = encrypt_data(plaintext, test_secret_key)
    encrypted2 = encrypt_data(plaintext, test_secret_key)

    # Assert
    assert encrypted1 != encrypted2  # Diferentes por nonce aleatorio
    # Pero ambos descifran al mismo texto
    assert decrypt_data(encrypted1, test_secret_key) == plaintext
    assert decrypt_data(encrypted2, test_secret_key) == plaintext


def test_decrypt_data_empty_string(test_secret_key):
    """Test descifrado de string vacío."""
    # Act
    result = decrypt_data("", test_secret_key)

    # Assert
    assert result == ""


def test_decrypt_data_wrong_key(test_secret_key):
    """Test error al descifrar con clave incorrecta."""
    # Arrange
    plaintext = "Secret data"
    correct_key = test_secret_key
    wrong_key = b"wrong_key_32_bytes_long_here!!"
    encrypted = encrypt_data(plaintext, correct_key)

    # Act & Assert
    with pytest.raises(ValueError, match="Error al descifrar datos"):
        decrypt_data(encrypted, wrong_key)


def test_decrypt_data_corrupted_ciphertext(test_secret_key):
    """Test error al descifrar datos corruptos."""
    # Arrange
    plaintext = "Secret data"
    encrypted = encrypt_data(plaintext, test_secret_key)
    # Corromper el ciphertext
    encrypted_bytes = base64.b64decode(encrypted)
    corrupted = encrypted_bytes[:-1] + b"X"  # Cambiar último byte
    corrupted_b64 = base64.b64encode(corrupted).decode("ascii")

    # Act & Assert
    with pytest.raises(ValueError, match="Error al descifrar datos"):
        decrypt_data(corrupted_b64, test_secret_key)


def test_decrypt_data_invalid_base64(test_secret_key):
    """Test error con Base64 inválido."""
    # Arrange
    invalid_b64 = "not-valid-base64!@#"

    # Act & Assert
    with pytest.raises(Exception):  # base64.b64decode lanza Exception
        decrypt_data(invalid_b64, test_secret_key)


def test_encrypt_data_unicode_characters(test_secret_key):
    """Test cifrado de caracteres Unicode."""
    # Arrange
    unicode_texts = [
        "中文密码",  # Chino
        "пароль",  # Ruso
        "パスワード",  # Japonés
        "كلمة السر",  # Árabe
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
    """Test creación de DecryptedCredential."""
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
    """Test DecryptedCredential con campos opcionales en None."""
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
    """Test creación de LoginKeys."""
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
# TESTS: Constantes
# ============================================================================


def test_crypto_constants():
    """Test que las constantes tienen los valores esperados."""
    # Assert - Verificar tamaños según libsodium
    assert PRIMARY_KEY_SIZE == 32
    assert SECRET_KEY_SIZE == 32
    assert HASH_SIZE == 32
    assert STRETCHED_PRIMARY_KEY_SIZE == 32
    assert NONCE_SIZE == 24
    assert KDF_PERSONAL_SIZE == 16

    # Verificar contextos KDF
    assert len(KDF_CONTEXT_PASSWORD) == 8
    assert len(KDF_CONTEXT_STRETCHED) == 8
    assert KDF_CONTEXT_PASSWORD == b"Password"
    assert KDF_CONTEXT_STRETCHED == b"Stretchy"

    # Verificar subkey IDs
    assert SUBKEY_ID_PASSWORD_HASH == 1
    assert SUBKEY_ID_STRETCHED_PK == 2
