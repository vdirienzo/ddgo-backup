"""
crypto.py - Implementación criptográfica compatible con DDG Sync

Autor: Homero Thompson del Lago del Terror

Reimplementa la criptografía de libsodium usada por DuckDuckGo:
- Argon2i para derivación de password → primaryKey
- BLAKE2b KDF para derivar stretchedPrimaryKey y passwordHash
- XSalsa20-Poly1305 para cifrado/descifrado de datos
"""

import base64
import struct
from dataclasses import dataclass

import nacl.bindings
import nacl.secret
import nacl.utils
from nacl.bindings import (
    crypto_generichash_blake2b_salt_personal,
    crypto_secretbox_open,
)
from nacl.encoding import RawEncoder

# Constantes de libsodium (mismas que DDGSyncCrypto.h)
PRIMARY_KEY_SIZE = 32
SECRET_KEY_SIZE = 32
HASH_SIZE = 32
STRETCHED_PRIMARY_KEY_SIZE = 32

# Parámetros Argon2i INTERACTIVE (no usados en login, solo en creación de cuenta)
ARGON2_OPSLIMIT = nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
ARGON2_MEMLIMIT = nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
ARGON2_ALG = nacl.bindings.crypto_pwhash_ALG_ARGON2I13

# Contextos KDF (exactamente 8 caracteres, se paddean a 16)
KDF_CONTEXT_STRETCHED = b"Stretchy"
KDF_CONTEXT_PASSWORD = b"Password"

# Subkey IDs (según DDGSyncCrypto.c)
SUBKEY_ID_PASSWORD_HASH = 1
SUBKEY_ID_STRETCHED_PK = 2

# Tamaños de nonce y MAC
NONCE_SIZE = nacl.bindings.crypto_secretbox_NONCEBYTES  # 24 bytes
MAC_SIZE = nacl.bindings.crypto_secretbox_MACBYTES  # 16 bytes
SALT_SIZE = nacl.bindings.crypto_pwhash_SALTBYTES  # 16 bytes

# Tamaños para BLAKE2b KDF
KDF_SALT_SIZE = nacl.bindings.crypto_generichash_SALTBYTES  # 16 bytes
KDF_PERSONAL_SIZE = nacl.bindings.crypto_generichash_PERSONALBYTES  # 16 bytes


@dataclass
class LoginKeys:
    """Claves derivadas para login."""

    password_hash: bytes
    stretched_primary_key: bytes
    primary_key: bytes


@dataclass
class DecryptedCredential:
    """Credencial descifrada."""

    domain: str
    username: str
    password: str
    notes: str | None = None
    title: str | None = None


def _kdf_derive_from_key(
    subkey_size: int,
    subkey_id: int,
    context: bytes,
    key: bytes,
) -> bytes:
    """
    Reimplementa crypto_kdf_derive_from_key de libsodium.

    Usa BLAKE2b con:
    - Salt: subkey_id como uint64 LE + 8 bytes de zeros (16 bytes total)
    - Personal: context padded con zeros hasta 16 bytes

    Args:
        subkey_size: Tamaño de la subclave a derivar (16-64 bytes)
        subkey_id: ID numérico de la subclave
        context: Contexto de 8 bytes
        key: Clave maestra de 32 bytes

    Returns:
        bytes: Subclave derivada
    """
    if len(context) > KDF_PERSONAL_SIZE:
        raise ValueError(f"Context debe ser <= {KDF_PERSONAL_SIZE} bytes")

    # Construir salt: subkey_id como uint64 LE + padding zeros
    salt = struct.pack("<Q", subkey_id) + b"\x00" * 8  # 8 + 8 = 16 bytes

    # Construir personal: context + padding zeros
    personal = context.ljust(KDF_PERSONAL_SIZE, b"\x00")

    # BLAKE2b con salt y personal
    # crypto_generichash_blake2b_salt_personal espera data vacío y key como la master key
    subkey = crypto_generichash_blake2b_salt_personal(
        data=b"",
        digest_size=subkey_size,
        key=key,
        salt=salt,
        person=personal,
    )

    return subkey


def decode_recovery_code(recovery_code: str) -> tuple[str, str]:
    """
    Decodifica un Recovery Code de DuckDuckGo.

    El recovery code es JSON en Base64:
    {"recovery": {"primary_key": "xxx", "user_id": "yyy"}}

    NOTA: El PDF de DuckDuckGo muestra el código en múltiples líneas.
    Esta función limpia automáticamente saltos de línea, espacios, etc.

    Returns:
        tuple[str, str]: (primary_key_b64, user_id)
    """
    import json
    import re

    # Limpiar el código exhaustivamente
    # El PDF de DDG divide el código en 3-4 líneas, así que hay que limpiarlo bien
    clean_code = recovery_code

    # Eliminar todos los caracteres de espacio en blanco (espacios, tabs, newlines, etc.)
    clean_code = re.sub(r'\s+', '', clean_code)

    # Eliminar guiones (por si lo formatearon manualmente)
    clean_code = clean_code.replace("-", "")

    # Eliminar comillas que puedan haber quedado al copiar
    clean_code = clean_code.replace('"', '').replace("'", "")

    # Intentar decodificar Base64
    try:
        decoded = base64.b64decode(clean_code)
        data = json.loads(decoded)
    except Exception:
        # Intentar con URL-safe Base64
        try:
            # Agregar padding si es necesario
            padding = 4 - (len(clean_code) % 4)
            if padding != 4:
                clean_code += "=" * padding
            decoded = base64.urlsafe_b64decode(clean_code)
            data = json.loads(decoded)
        except Exception as e:
            raise ValueError(
                f"Recovery code inválido. Asegúrate de copiar todo el código del PDF.\n"
                f"Error: {e}"
            ) from e

    # Extraer campos
    if "recovery" in data:
        recovery = data["recovery"]
        return recovery["primary_key"], recovery["user_id"]
    elif "primary_key" in data:
        return data["primary_key"], data["user_id"]
    else:
        raise ValueError("Formato de recovery code no reconocido")


def prepare_for_login(primary_key_b64: str) -> LoginKeys:
    """
    Prepara las claves necesarias para login desde la primaryKey.

    Replica la función ddgSyncPrepareForLogin de DDGSyncCrypto.c:
    1. Deriva passwordHash usando KDF con contexto "Password" (subkey_id=1)
    2. Deriva stretchedPrimaryKey usando KDF con contexto "Stretchy" (subkey_id=2)

    Args:
        primary_key_b64: Primary key en Base64

    Returns:
        LoginKeys con password_hash, stretched_primary_key, y primary_key
    """
    # Decodificar primaryKey
    primary_key = base64.b64decode(primary_key_b64)

    if len(primary_key) != PRIMARY_KEY_SIZE:
        raise ValueError(
            f"Primary key debe ser {PRIMARY_KEY_SIZE} bytes, "
            f"recibido {len(primary_key)}"
        )

    # Derivar passwordHash (subkey_id=1, contexto="Password")
    password_hash = _kdf_derive_from_key(
        subkey_size=HASH_SIZE,
        subkey_id=SUBKEY_ID_PASSWORD_HASH,
        context=KDF_CONTEXT_PASSWORD,
        key=primary_key,
    )

    # Derivar stretchedPrimaryKey (subkey_id=2, contexto="Stretchy")
    stretched_pk = _kdf_derive_from_key(
        subkey_size=STRETCHED_PRIMARY_KEY_SIZE,
        subkey_id=SUBKEY_ID_STRETCHED_PK,
        context=KDF_CONTEXT_STRETCHED,
        key=primary_key,
    )

    return LoginKeys(
        password_hash=password_hash,
        stretched_primary_key=stretched_pk,
        primary_key=primary_key,
    )


def decrypt_protected_secret_key(
    protected_secret_key_b64: str, stretched_primary_key: bytes
) -> bytes:
    """
    Descifra la secretKey protegida usando stretchedPrimaryKey.

    El formato es: [ciphertext + MAC][nonce]
    - MAC: 16 bytes (al final del ciphertext)
    - Nonce: 24 bytes (al final de todo)

    Args:
        protected_secret_key_b64: Protected secret key en Base64
        stretched_primary_key: Clave para descifrar

    Returns:
        bytes: Secret key descifrada (32 bytes)
    """
    encrypted = base64.b64decode(protected_secret_key_b64)

    # Extraer nonce (últimos 24 bytes)
    nonce = encrypted[-NONCE_SIZE:]
    ciphertext = encrypted[:-NONCE_SIZE]

    # Descifrar usando XSalsa20-Poly1305
    try:
        secret_key = crypto_secretbox_open(
            ciphertext=ciphertext,
            nonce=nonce,
            key=stretched_primary_key,
        )
    except Exception as e:
        raise ValueError(f"Error al descifrar secret key: {e}") from e

    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(
            f"Secret key descifrada tiene tamaño incorrecto: {len(secret_key)}"
        )

    return secret_key


def decrypt_data(encrypted_b64: str, secret_key: bytes) -> str:
    """
    Descifra datos sincronizados usando la secretKey.

    El formato es el mismo que protected_secret_key:
    [ciphertext + MAC][nonce]

    Args:
        encrypted_b64: Datos cifrados en Base64
        secret_key: Clave secreta (32 bytes)

    Returns:
        str: Datos descifrados como string UTF-8
    """
    if not encrypted_b64:
        return ""

    encrypted = base64.b64decode(encrypted_b64)

    # Extraer nonce (últimos 24 bytes)
    nonce = encrypted[-NONCE_SIZE:]
    ciphertext = encrypted[:-NONCE_SIZE]

    # Descifrar
    try:
        plaintext = crypto_secretbox_open(
            ciphertext=ciphertext,
            nonce=nonce,
            key=secret_key,
        )
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Error al descifrar datos: {e}") from e


def encrypt_data(plaintext: str, secret_key: bytes) -> str:
    """
    Cifra datos usando la secretKey.

    Args:
        plaintext: Texto a cifrar
        secret_key: Clave secreta (32 bytes)

    Returns:
        str: Datos cifrados en Base64
    """
    # Generar nonce aleatorio
    nonce = nacl.utils.random(NONCE_SIZE)

    # Cifrar usando XSalsa20-Poly1305
    box = nacl.secret.SecretBox(secret_key)
    ciphertext = box.encrypt(plaintext.encode("utf-8"), nonce, encoder=RawEncoder)

    # El formato de PyNaCl ya incluye nonce al inicio, pero DDG lo pone al final
    # ciphertext de PyNaCl = nonce + ciphertext_real
    # Necesitamos: ciphertext_real + nonce
    actual_ciphertext = ciphertext[NONCE_SIZE:]
    result = actual_ciphertext + nonce

    return base64.b64encode(result).decode("ascii")
