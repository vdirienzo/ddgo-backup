"""
api.py - Cliente HTTP para la API de DuckDuckGo Sync

Autor: Homero Thompson del Lago del Terror

Implementa los endpoints necesarios para:
1. Login con userId y passwordHash
2. Fetch de credenciales sincronizadas
"""

import base64
from dataclasses import dataclass, field

import httpx
from loguru import logger

from .crypto import LoginKeys, decrypt_data, decrypt_protected_secret_key
from .models import DecryptedCredential, Device

# URLs de la API
SYNC_API_BASE = "https://sync.duckduckgo.com"


@dataclass
class SyncClient:
    """Cliente para la API de sincronización de DuckDuckGo."""

    user_id: str
    login_keys: LoginKeys
    token: str | None = None
    secret_key: bytes | None = None
    devices: list[Device] = field(default_factory=list)
    _http: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=30.0))

    def login(self, device_id: str = "backup-tool", device_name: str = "DDG Backup") -> bool:
        """
        Autentica con el servidor de sync.

        Args:
            device_id: ID único del dispositivo
            device_name: Nombre legible del dispositivo

        Returns:
            bool: True si el login fue exitoso
        """
        logger.info(f"Iniciando login para user_id: {self.user_id[:8]}...")

        # Preparar payload
        # La API requiere que device_name y device_type estén en Base64
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

        # Hacer request
        response = self._http.post(
            f"{SYNC_API_BASE}/sync/login",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 401:
            logger.error("Credenciales inválidas")
            raise ValueError("Credenciales inválidas - verifica tu Recovery Code")

        if response.status_code != 200:
            logger.error(f"Error de login: {response.status_code} - {response.text}")
            raise ValueError(f"Error de login: {response.status_code}")

        data = response.json()
        logger.debug(f"Respuesta login: {list(data.keys())}")

        # Extraer token y protected_encryption_key
        self.token = data.get("token")
        protected_key = data.get("protected_encryption_key")

        if not self.token or not protected_key:
            raise ValueError("Respuesta de login incompleta")

        # Descifrar secret key
        self.secret_key = decrypt_protected_secret_key(
            protected_key, self.login_keys.stretched_primary_key
        )

        # Parsear dispositivos
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
            f"Login exitoso. {len(self.devices)} dispositivo(s) en la cuenta."
        )
        return True

    def fetch_credentials(self) -> list[DecryptedCredential]:
        """
        Obtiene y descifra todas las credenciales.

        Returns:
            list[DecryptedCredential]: Lista de credenciales descifradas
        """
        if not self.token or not self.secret_key:
            raise ValueError("Debes hacer login primero")

        logger.info("Obteniendo credenciales...")

        response = self._http.get(
            f"{SYNC_API_BASE}/sync/credentials",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )

        if response.status_code != 200:
            logger.error(f"Error al obtener credenciales: {response.status_code}")
            raise ValueError(f"Error al obtener credenciales: {response.status_code}")

        data = response.json()
        logger.debug(f"Respuesta credentials: {list(data.keys())}")

        # Parsear y descifrar credenciales
        credentials = []
        entries = data.get("entries", data.get("credentials", {}).get("entries", []))

        if isinstance(entries, dict):
            entries = entries.get("entries", [])

        logger.info(f"Procesando {len(entries)} credenciales...")

        for entry in entries:
            try:
                cred = self._decrypt_credential(entry)
                if cred:
                    credentials.append(cred)
            except Exception as e:
                logger.warning(f"Error al descifrar credencial: {e}")
                continue

        logger.success(f"Descifradas {len(credentials)} credenciales exitosamente")
        return credentials

    def _decrypt_credential(self, entry: dict) -> DecryptedCredential | None:
        """Descifra una entrada de credencial individual."""
        # TODOS los campos vienen cifrados desde el servidor
        # Función helper para descifrar un campo
        def decrypt_field(field_name: str) -> str:
            value = entry.get(field_name, "")
            if not value:
                return ""
            try:
                return decrypt_data(value, self.secret_key)
            except Exception:
                return value  # Retornar original si falla

        # Descifrar todos los campos
        domain = decrypt_field("domain")
        username = decrypt_field("username")
        password = decrypt_field("password")
        notes = decrypt_field("notes")
        title = decrypt_field("title") or decrypt_field("domainTitle")

        # Solo retornar si tenemos datos útiles
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
        """Heurística para detectar si un string parece Base64 cifrado."""
        if len(s) < 40:
            return False
        try:
            decoded = base64.b64decode(s)
            return len(decoded) > 24  # Mínimo: MAC + nonce
        except Exception:
            return False

    def close(self):
        """Cierra el cliente HTTP."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
