"""
models.py - Modelos de datos para la API de DuckDuckGo Sync

Autor: Homero Thompson del Lago del Terror
"""

from pydantic import BaseModel, Field


class Device(BaseModel):
    """Dispositivo registrado en la cuenta."""

    id: str
    name: str
    type: str | None = None


class LoginResponse(BaseModel):
    """Respuesta del endpoint /sync/login."""

    token: str
    protected_encryption_key: str
    devices: list[Device] = Field(default_factory=list)


class CredentialEntry(BaseModel):
    """Entrada de credencial sincronizada (formato del servidor)."""

    id: str
    domain: str | None = None
    username: str | None = None
    password: str | None = None  # Cifrado
    notes: str | None = None  # Cifrado
    title: str | None = None
    last_modified: str | None = None


class CredentialsResponse(BaseModel):
    """Respuesta del endpoint /sync/credentials."""

    credentials: dict  # Estructura JSON variable


class SyncDataResponse(BaseModel):
    """Respuesta genérica de sincronización."""

    entries: list[dict] = Field(default_factory=list)
    last_modified: str | None = None


class DecryptedCredential(BaseModel):
    """Credencial descifrada lista para exportar."""

    id: str | None = None
    domain: str
    username: str
    password: str
    notes: str | None = None
    title: str | None = None

    def to_csv_row(self) -> dict[str, str]:
        """Convierte a fila para CSV."""
        return {
            "site": self.domain or "",
            "username": self.username or "",
            "password": self.password or "",
            "notes": self.notes or "",
            "title": self.title or "",
        }
