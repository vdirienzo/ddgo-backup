"""
crypto.py - Cryptographic implementation compatible with DDG Sync

Author: Homero Thompson del Lago del Terror

Re-implements the libsodium cryptography used by DuckDuckGo:
- Argon2i for password derivation → primaryKey
- BLAKE2b KDF to derive stretchedPrimaryKey and passwordHash
- XSalsa20-Poly1305 for data encryption/decryption
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

# libsodium constants (same as DDGSyncCrypto.h)
PRIMARY_KEY_SIZE = 32
SECRET_KEY_SIZE = 32
HASH_SIZE = 32
STRETCHED_PRIMARY_KEY_SIZE = 32

# Argon2i INTERACTIVE parameters (not used in login, only in account creation)
ARGON2_OPSLIMIT = nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
ARGON2_MEMLIMIT = nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
ARGON2_ALG = nacl.bindings.crypto_pwhash_ALG_ARGON2I13

# KDF contexts (exactly 8 characters, padded to 16)
KDF_CONTEXT_STRETCHED = b"Stretchy"
KDF_CONTEXT_PASSWORD = b"Password"

# Subkey IDs (according to DDGSyncCrypto.c)
SUBKEY_ID_PASSWORD_HASH = 1
SUBKEY_ID_STRETCHED_PK = 2

# Nonce and MAC sizes
NONCE_SIZE = nacl.bindings.crypto_secretbox_NONCEBYTES  # 24 bytes
MAC_SIZE = nacl.bindings.crypto_secretbox_MACBYTES  # 16 bytes
SALT_SIZE = nacl.bindings.crypto_pwhash_SALTBYTES  # 16 bytes

# BLAKE2b KDF sizes
KDF_SALT_SIZE = nacl.bindings.crypto_generichash_SALTBYTES  # 16 bytes
KDF_PERSONAL_SIZE = nacl.bindings.crypto_generichash_PERSONALBYTES  # 16 bytes


@dataclass
class LoginKeys:
    """Derived keys for login."""

    password_hash: bytes
    stretched_primary_key: bytes
    primary_key: bytes


@dataclass
class DecryptedCredential:
    """Decrypted credential."""

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
    Re-implements crypto_kdf_derive_from_key from libsodium.

    Uses BLAKE2b with:
    - Salt: subkey_id as uint64 LE + 8 bytes of zeros (16 bytes total)
    - Personal: context padded with zeros to 16 bytes

    Args:
        subkey_size: Size of the subkey to derive (16-64 bytes)
        subkey_id: Numeric ID of the subkey
        context: 8-byte context
        key: 32-byte master key

    Returns:
        bytes: Derived subkey
    """
    if len(context) > KDF_PERSONAL_SIZE:
        raise ValueError(f"Context must be <= {KDF_PERSONAL_SIZE} bytes")

    # Build salt: subkey_id as uint64 LE + padding zeros
    salt = struct.pack("<Q", subkey_id) + b"\x00" * 8  # 8 + 8 = 16 bytes

    # Build personal: context + padding zeros
    personal = context.ljust(KDF_PERSONAL_SIZE, b"\x00")

    # BLAKE2b with salt and personal
    # crypto_generichash_blake2b_salt_personal expects empty data and key as master key
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
    Decode a DuckDuckGo Recovery Code.

    The recovery code is JSON encoded in Base64:
    {"recovery": {"primary_key": "xxx", "user_id": "yyy"}}

    NOTE: The DuckDuckGo PDF shows the code in multiple lines.
    This function automatically cleans line breaks, spaces, etc.

    Returns:
        tuple[str, str]: (primary_key_b64, user_id)
    """
    import json
    import re

    # Clean the code exhaustively
    # The DDG PDF splits the code into 3-4 lines, so it needs thorough cleaning
    clean_code = recovery_code

    # Remove all whitespace characters (spaces, tabs, newlines, etc.)
    clean_code = re.sub(r"\s+", "", clean_code)

    # Remove dashes (in case it was manually formatted)
    clean_code = clean_code.replace("-", "")

    # Remove quotes that may have been left over when copying
    clean_code = clean_code.replace('"', "").replace("'", "")

    # Try to decode Base64
    try:
        decoded = base64.b64decode(clean_code)
        data = json.loads(decoded)
    except Exception:
        # Try URL-safe Base64
        try:
            # Add padding if needed
            padding = 4 - (len(clean_code) % 4)
            if padding != 4:
                clean_code += "=" * padding
            decoded = base64.urlsafe_b64decode(clean_code)
            data = json.loads(decoded)
        except Exception as e:
            raise ValueError(
                f"Invalid recovery code. Make sure to copy the entire code from the PDF.\n"
                f"Error: {e}"
            ) from e

    # Extract fields
    if "recovery" in data:
        recovery = data["recovery"]
        return recovery["primary_key"], recovery["user_id"]
    elif "primary_key" in data:
        return data["primary_key"], data["user_id"]
    else:
        raise ValueError("Unrecognized recovery code format")


def prepare_for_login(primary_key_b64: str) -> LoginKeys:
    """
    Prepare the keys needed for login from the primaryKey.

    Replicates the ddgSyncPrepareForLogin function from DDGSyncCrypto.c:
    1. Derives passwordHash using KDF with context "Password" (subkey_id=1)
    2. Derives stretchedPrimaryKey using KDF with context "Stretchy" (subkey_id=2)

    Args:
        primary_key_b64: Primary key in Base64

    Returns:
        LoginKeys with password_hash, stretched_primary_key, and primary_key
    """
    # Decode primaryKey
    primary_key = base64.b64decode(primary_key_b64)

    if len(primary_key) != PRIMARY_KEY_SIZE:
        raise ValueError(
            f"Primary key must be {PRIMARY_KEY_SIZE} bytes, received {len(primary_key)}"
        )

    # Derive passwordHash (subkey_id=1, context="Password")
    password_hash = _kdf_derive_from_key(
        subkey_size=HASH_SIZE,
        subkey_id=SUBKEY_ID_PASSWORD_HASH,
        context=KDF_CONTEXT_PASSWORD,
        key=primary_key,
    )

    # Derive stretchedPrimaryKey (subkey_id=2, context="Stretchy")
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
    Decrypt the protected secretKey using stretchedPrimaryKey.

    The format is: [ciphertext + MAC][nonce]
    - MAC: 16 bytes (at the end of ciphertext)
    - Nonce: 24 bytes (at the very end)

    Args:
        protected_secret_key_b64: Protected secret key in Base64
        stretched_primary_key: Key to decrypt with

    Returns:
        bytes: Decrypted secret key (32 bytes)
    """
    encrypted = base64.b64decode(protected_secret_key_b64)

    # Extract nonce (last 24 bytes)
    nonce = encrypted[-NONCE_SIZE:]
    ciphertext = encrypted[:-NONCE_SIZE]

    # Decrypt using XSalsa20-Poly1305
    try:
        secret_key = crypto_secretbox_open(
            ciphertext=ciphertext,
            nonce=nonce,
            key=stretched_primary_key,
        )
    except Exception as e:
        raise ValueError(f"Error decrypting secret key: {e}") from e

    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(f"Decrypted secret key has incorrect size: {len(secret_key)}")

    return secret_key


def decrypt_data(encrypted_b64: str, secret_key: bytes) -> str:
    """
    Decrypt synced data using the secretKey.

    The format is the same as protected_secret_key:
    [ciphertext + MAC][nonce]

    Args:
        encrypted_b64: Encrypted data in Base64
        secret_key: Secret key (32 bytes)

    Returns:
        str: Decrypted data as UTF-8 string
    """
    if not encrypted_b64:
        return ""

    encrypted = base64.b64decode(encrypted_b64)

    # Extract nonce (last 24 bytes)
    nonce = encrypted[-NONCE_SIZE:]
    ciphertext = encrypted[:-NONCE_SIZE]

    # Decrypt
    try:
        plaintext = crypto_secretbox_open(
            ciphertext=ciphertext,
            nonce=nonce,
            key=secret_key,
        )
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Error decrypting data: {e}") from e


def encrypt_data(plaintext: str, secret_key: bytes) -> str:
    """
    Encrypt data using the secretKey.

    Args:
        plaintext: Text to encrypt
        secret_key: Secret key (32 bytes)

    Returns:
        str: Encrypted data in Base64
    """
    # Generate random nonce
    nonce = nacl.utils.random(NONCE_SIZE)

    # Encrypt using XSalsa20-Poly1305
    box = nacl.secret.SecretBox(secret_key)
    ciphertext = box.encrypt(plaintext.encode("utf-8"), nonce, encoder=RawEncoder)

    # PyNaCl format already includes nonce at the beginning, but DDG puts it at the end
    # PyNaCl ciphertext = nonce + actual_ciphertext
    # We need: actual_ciphertext + nonce
    actual_ciphertext = ciphertext[NONCE_SIZE:]
    result = actual_ciphertext + nonce

    return base64.b64encode(result).decode("ascii")
