"""
api.py - HTTP client for the DuckDuckGo Sync API

Author: Homero Thompson del Lago del Terror

Implements the required endpoints for:
1. Login with userId and passwordHash
2. Fetch synced credentials
"""

import base64
from dataclasses import dataclass, field

import httpx
from loguru import logger

from .crypto import LoginKeys, decrypt_data, decrypt_protected_secret_key
from .models import DecryptedCredential, Device

# API URLs
SYNC_API_BASE = "https://sync.duckduckgo.com"


@dataclass
class SyncClient:
    """Client for the DuckDuckGo sync API."""

    user_id: str
    login_keys: LoginKeys
    token: str | None = None
    secret_key: bytes | None = None
    devices: list[Device] = field(default_factory=list)
    _http: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=30.0))

    def login(
        self, device_id: str = "backup-tool", device_name: str = "DDG Backup"
    ) -> bool:
        """
        Authenticate with the sync server.

        Args:
            device_id: Unique device ID
            device_name: Human-readable device name

        Returns:
            bool: True if login was successful
        """
        logger.info(f"Starting login for user_id: {self.user_id[:8]}...")

        # Prepare payload
        # The API requires device_name and device_type to be in Base64
        password_hash_b64 = base64.b64encode(self.login_keys.password_hash).decode()
        device_name_b64 = base64.b64encode(device_name.encode()).decode()
        device_type_b64 = base64.b64encode(b"desktop").decode()

        payload = {
            "user_id": self.user_id,
            "hashed_password": password_hash_b64,
            "device_id": device_id,
            "device_name": device_name_b64,
            "device_type": device_type_b64,
        }

        # Make request
        response = self._http.post(
            f"{SYNC_API_BASE}/sync/login",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 401:
            logger.error("Invalid credentials")
            raise ValueError("Invalid credentials - verify your Recovery Code")

        if response.status_code != 200:
            logger.error(f"Login error: {response.status_code} - {response.text}")
            raise ValueError(f"Login error: {response.status_code}")

        data = response.json()
        logger.debug(f"Login response: {list(data.keys())}")

        # Extract token and protected_encryption_key
        self.token = data.get("token")
        protected_key = data.get("protected_encryption_key")

        if not self.token or not protected_key:
            raise ValueError("Incomplete login response")

        # Decrypt secret key
        self.secret_key = decrypt_protected_secret_key(
            protected_key, self.login_keys.stretched_primary_key
        )

        # Parse devices
        devices_data = data.get("devices", [])
        self.devices = [
            Device(
                id=d.get("id", ""),
                name=d.get("name", "Unknown"),
                type=d.get("type"),
            )
            for d in devices_data
        ]

        logger.success(
            f"Login successful. {len(self.devices)} device(s) in the account."
        )
        return True

    def fetch_credentials(self) -> list[DecryptedCredential]:
        """
        Fetch and decrypt all credentials.

        Returns:
            list[DecryptedCredential]: List of decrypted credentials
        """
        if not self.token or not self.secret_key:
            raise ValueError("You must login first")

        logger.info("Fetching credentials...")

        response = self._http.get(
            f"{SYNC_API_BASE}/sync/credentials",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )

        if response.status_code != 200:
            logger.error(f"Error fetching credentials: {response.status_code}")
            raise ValueError(f"Error fetching credentials: {response.status_code}")

        data = response.json()
        logger.debug(f"Credentials response: {list(data.keys())}")

        # Parse and decrypt credentials
        credentials = []
        entries = data.get("entries", data.get("credentials", {}).get("entries", []))

        if isinstance(entries, dict):
            entries = entries.get("entries", [])

        logger.info(f"Processing {len(entries)} credentials...")

        for entry in entries:
            try:
                cred = self._decrypt_credential(entry)
                if cred:
                    credentials.append(cred)
            except Exception as e:
                logger.warning(f"Error decrypting credential: {e}")
                continue

        logger.success(f"Decrypted {len(credentials)} credentials successfully")
        return credentials

    def _decrypt_credential(self, entry: dict) -> DecryptedCredential | None:
        """Decrypt an individual credential entry."""

        # ALL fields come encrypted from the server
        # Helper function to decrypt a field
        def decrypt_field(field_name: str) -> str:
            value: str = entry.get(field_name, "") or ""
            if not value:
                return ""
            # self.secret_key was already verified in fetch_credentials (line 115)
            if self.secret_key is None:
                return str(value)
            try:
                return decrypt_data(value, self.secret_key)
            except Exception:
                return str(value)  # Return original if decryption fails

        # Decrypt all fields
        domain = decrypt_field("domain")
        username = decrypt_field("username")
        password = decrypt_field("password")
        notes = decrypt_field("notes")
        title = decrypt_field("title") or decrypt_field("domainTitle")

        # Only return if we have useful data
        if not domain and not username and not password:
            return None

        return DecryptedCredential(
            id=entry.get("id"),
            domain=domain or "unknown",
            username=username or "",
            password=password,
            notes=notes if notes else None,
            title=title if title else None,
        )

    def _looks_like_base64(self, s: str) -> bool:
        """Heuristic to detect if a string looks like encrypted Base64."""
        if len(s) < 40:
            return False
        try:
            decoded = base64.b64decode(s)
            return len(decoded) > 24  # Minimum: MAC + nonce
        except Exception:
            return False

    def close(self):
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
