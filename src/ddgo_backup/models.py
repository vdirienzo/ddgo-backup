"""
models.py - Data models for the DuckDuckGo Sync API

Author: Homero Thompson del Lago del Terror
"""

from pydantic import BaseModel, Field


class Device(BaseModel):
    """Device registered in the account."""

    id: str
    name: str
    type: str | None = None


class LoginResponse(BaseModel):
    """Response from the /sync/login endpoint."""

    token: str
    protected_encryption_key: str
    devices: list[Device] = Field(default_factory=list)


class CredentialEntry(BaseModel):
    """Synced credential entry (server format)."""

    id: str
    domain: str | None = None
    username: str | None = None
    password: str | None = None  # Encrypted
    notes: str | None = None  # Encrypted
    title: str | None = None
    last_modified: str | None = None


class CredentialsResponse(BaseModel):
    """Response from the /sync/credentials endpoint."""

    credentials: dict  # Variable JSON structure


class SyncDataResponse(BaseModel):
    """Generic sync response."""

    entries: list[dict] = Field(default_factory=list)
    last_modified: str | None = None


class DecryptedCredential(BaseModel):
    """Decrypted credential ready for export."""

    id: str | None = None
    domain: str
    username: str
    password: str
    notes: str | None = None
    title: str | None = None

    def to_csv_row(self) -> dict[str, str]:
        """Convert to CSV row."""
        return {
            "site": self.domain or "",
            "username": self.username or "",
            "password": self.password or "",
            "notes": self.notes or "",
            "title": self.title or "",
        }
