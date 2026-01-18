"""
test_exporter.py - Tests unitarios para funciones de exportación

Autor: Homero Thompson del Lago del Terror
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from ddgo_backup.exporter import (
    export_to_1password,
    export_to_bitwarden,
    export_to_csv,
    export_to_json,
    export_to_keeper,
    export_to_nordpass,
    export_to_protonpass,
    export_to_roboform,
)
from ddgo_backup.models import DecryptedCredential

# ============================================================================
# TESTS: export_to_csv
# ============================================================================


def test_export_to_csv_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación CSV con path especificado."""
    # Arrange
    output_file = tmp_path / "test_export.csv"

    # Act
    result_path = export_to_csv(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["name"] == "github.com"
    assert rows[0]["username"] == "testuser"
    assert rows[0]["password"] == "testpass123"
    assert rows[0]["title"] == "GitHub"


def test_export_to_csv_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación CSV con path por defecto."""
    # Act
    result_path = export_to_csv(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_passwords_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_csv_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_csv(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = ["name", "url", "username", "password", "notes", "title"]
    assert fieldnames == expected_columns


def test_export_to_csv_handles_none_values(tmp_path: Path):
    """Test que CSV maneja correctamente valores None."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="example.com",
            username="user",
            password="pass",
            notes=None,
            title=None,
        )
    ]
    output_file = tmp_path / "test.csv"

    # Act
    export_to_csv(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert rows[0]["notes"] == ""
    assert rows[0]["title"] == ""


# ============================================================================
# TESTS: export_to_json
# ============================================================================


def test_export_to_json_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación JSON con path especificado."""
    # Arrange
    output_file = tmp_path / "test_export.json"

    # Act
    result_path = export_to_json(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_credentials"] == 3
    assert len(data["credentials"]) == 3
    assert "exported_at" in data


def test_export_to_json_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación JSON con path por defecto."""
    # Act
    result_path = export_to_json(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_passwords_")
    assert result_path.suffix == ".json"

    # Cleanup
    result_path.unlink()


def test_export_to_json_correct_structure(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que JSON tiene la estructura correcta."""
    # Arrange
    output_file = tmp_path / "test.json"

    # Act
    export_to_json(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Verificar estructura raíz
    assert "exported_at" in data
    assert "total_credentials" in data
    assert "credentials" in data

    # Verificar estructura de credenciales
    cred = data["credentials"][0]
    assert "site" in cred
    assert "username" in cred
    assert "password" in cred
    assert "notes" in cred
    assert "title" in cred

    # Verificar contenido
    assert cred["site"] == "github.com"
    assert cred["username"] == "testuser"
    assert cred["password"] == "testpass123"


def test_export_to_json_valid_timestamp(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que el timestamp en JSON es válido."""
    # Arrange
    output_file = tmp_path / "test.json"

    # Act
    export_to_json(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Verificar que el timestamp es parseable
    exported_at = datetime.fromisoformat(data["exported_at"])
    assert isinstance(exported_at, datetime)


# ============================================================================
# TESTS: export_to_bitwarden
# ============================================================================


def test_export_to_bitwarden_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación Bitwarden con path especificado."""
    # Arrange
    output_file = tmp_path / "test_bitwarden.json"

    # Act
    result_path = export_to_bitwarden(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["encrypted"] is False
    assert len(data["items"]) == 3


def test_export_to_bitwarden_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación Bitwarden con path por defecto."""
    # Act
    result_path = export_to_bitwarden(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_bitwarden_")
    assert result_path.suffix == ".json"

    # Cleanup
    result_path.unlink()


def test_export_to_bitwarden_correct_structure(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que Bitwarden JSON tiene la estructura correcta."""
    # Arrange
    output_file = tmp_path / "test.json"

    # Act
    export_to_bitwarden(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Verificar estructura raíz
    assert "encrypted" in data
    assert "items" in data

    # Verificar estructura de items
    item = data["items"][0]
    assert item["type"] == 1  # Login type
    assert "name" in item
    assert "notes" in item
    assert "login" in item

    # Verificar estructura de login
    login = item["login"]
    assert "uris" in login
    assert "username" in login
    assert "password" in login


def test_export_to_bitwarden_uris_format(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que URIs de Bitwarden tienen el formato correcto."""
    # Arrange
    output_file = tmp_path / "test.json"

    # Act
    export_to_bitwarden(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    item = data["items"][0]
    uris = item["login"]["uris"]

    assert len(uris) == 1
    assert uris[0]["uri"] == "https://github.com"


# ============================================================================
# TESTS: export_to_1password
# ============================================================================


def test_export_to_1password_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación 1Password con path especificado."""
    # Arrange
    output_file = tmp_path / "test_1password.csv"

    # Act
    result_path = export_to_1password(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["title"] == "GitHub"
    assert rows[0]["website"] == "https://github.com"


def test_export_to_1password_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación 1Password con path por defecto."""
    # Act
    result_path = export_to_1password(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_1password_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_1password_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que 1Password CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_1password(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = ["title", "website", "username", "password", "notes"]
    assert fieldnames == expected_columns


def test_export_to_1password_website_format(tmp_path: Path):
    """Test que 1Password formatea URLs correctamente."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="example.com", username="user", password="pass", notes="", title=""
        )
    ]
    output_file = tmp_path / "test.csv"

    # Act
    export_to_1password(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert rows[0]["website"] == "https://example.com"


# ============================================================================
# TESTS: export_to_protonpass
# ============================================================================


def test_export_to_protonpass_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación ProtonPass con path especificado."""
    # Arrange
    output_file = tmp_path / "test_protonpass.csv"

    # Act
    result_path = export_to_protonpass(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["name"] == "GitHub"
    assert rows[0]["url"] == "https://github.com"


def test_export_to_protonpass_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación ProtonPass con path por defecto."""
    # Act
    result_path = export_to_protonpass(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_protonpass_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_protonpass_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que ProtonPass CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_protonpass(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = ["name", "url", "username", "password", "note", "totp"]
    assert fieldnames == expected_columns


def test_export_to_protonpass_url_format(tmp_path: Path):
    """Test que ProtonPass agrega https:// a URLs."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="example.com", username="user", password="pass", notes="", title=""
        )
    ]
    output_file = tmp_path / "test.csv"

    # Act
    export_to_protonpass(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert rows[0]["url"] == "https://example.com"


def test_export_to_protonpass_totp_empty(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que ProtonPass deja TOTP vacío."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_protonpass(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        assert row["totp"] == ""


# ============================================================================
# TESTS: export_to_nordpass
# ============================================================================


def test_export_to_nordpass_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación NordPass con path especificado."""
    # Arrange
    output_file = tmp_path / "test_nordpass.csv"

    # Act
    result_path = export_to_nordpass(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["name"] == "GitHub"
    assert rows[0]["url"] == "https://github.com"


def test_export_to_nordpass_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación NordPass con path por defecto."""
    # Act
    result_path = export_to_nordpass(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_nordpass_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_nordpass_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que NordPass CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_nordpass(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = ["name", "url", "username", "password", "note"]
    assert fieldnames == expected_columns


def test_export_to_nordpass_url_format(tmp_path: Path):
    """Test que NordPass agrega https:// a URLs."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="example.com", username="user", password="pass", notes="", title=""
        )
    ]
    output_file = tmp_path / "test.csv"

    # Act
    export_to_nordpass(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert rows[0]["url"] == "https://example.com"


# ============================================================================
# TESTS: export_to_roboform
# ============================================================================


def test_export_to_roboform_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación RoboForm con path especificado."""
    # Arrange
    output_file = tmp_path / "test_roboform.csv"

    # Act
    result_path = export_to_roboform(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["Name"] == "GitHub"
    assert rows[0]["Url"] == "https://github.com"
    assert rows[0]["MatchUrl"] == "https://github.com"


def test_export_to_roboform_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación RoboForm con path por defecto."""
    # Act
    result_path = export_to_roboform(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_roboform_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_roboform_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que RoboForm CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_roboform(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = ["Name", "Url", "MatchUrl", "Login", "Pwd", "Note"]
    assert fieldnames == expected_columns


def test_export_to_roboform_match_url_equals_url(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que RoboForm tiene MatchUrl igual a Url."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_roboform(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        assert row["Url"] == row["MatchUrl"]


# ============================================================================
# TESTS: export_to_keeper
# ============================================================================


def test_export_to_keeper_with_specified_path(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test exportación Keeper con path especificado."""
    # Arrange
    output_file = tmp_path / "test_keeper.csv"

    # Act
    result_path = export_to_keeper(sample_decrypted_credentials, output_file)

    # Assert
    assert result_path == output_file
    assert output_file.exists()

    # Verificar contenido
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["Title"] == "GitHub"
    assert rows[0]["Website Address"] == "https://github.com"
    assert rows[0]["Folder"] == "DuckDuckGo Import"


def test_export_to_keeper_with_default_path(
    sample_decrypted_credentials: list[DecryptedCredential],
):
    """Test exportación Keeper con path por defecto."""
    # Act
    result_path = export_to_keeper(sample_decrypted_credentials)

    # Assert
    assert result_path.exists()
    assert result_path.name.startswith("ddg_keeper_")
    assert result_path.suffix == ".csv"

    # Cleanup
    result_path.unlink()


def test_export_to_keeper_correct_columns(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que Keeper CSV tiene las columnas correctas."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_keeper(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    expected_columns = [
        "Folder",
        "Title",
        "Login",
        "Password",
        "Website Address",
        "Notes",
    ]
    assert fieldnames == expected_columns


def test_export_to_keeper_default_folder(
    sample_decrypted_credentials: list[DecryptedCredential], tmp_path: Path
):
    """Test que Keeper usa carpeta por defecto."""
    # Arrange
    output_file = tmp_path / "test.csv"

    # Act
    export_to_keeper(sample_decrypted_credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        assert row["Folder"] == "DuckDuckGo Import"


# ============================================================================
# TESTS: Edge Cases
# ============================================================================


def test_export_empty_credentials_list(tmp_path: Path):
    """Test exportación con lista vacía de credenciales."""
    # Arrange
    credentials: list[DecryptedCredential] = []
    csv_file = tmp_path / "empty.csv"
    json_file = tmp_path / "empty.json"

    # Act
    export_to_csv(credentials, csv_file)
    export_to_json(credentials, json_file)

    # Assert - archivos existen pero sin contenido
    assert csv_file.exists()
    assert json_file.exists()

    # CSV solo tiene header
    with csv_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 0

    # JSON tiene estructura correcta
    with json_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_credentials"] == 0
    assert data["credentials"] == []


def test_export_with_special_characters(tmp_path: Path):
    """Test exportación con caracteres especiales."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="example.com",
            username="user@email.com",
            password='p@$$w0rd!"#$',
            notes="Notas con\ncaracteres especiales: áéíóú",
            title="Título con 中文",
        )
    ]
    output_file = tmp_path / "special.csv"

    # Act
    export_to_csv(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert rows[0]["username"] == "user@email.com"
    assert rows[0]["password"] == 'p@$$w0rd!"#$'
    assert "áéíóú" in rows[0]["notes"]
    assert "中文" in rows[0]["title"]


def test_export_preserves_url_with_protocol(tmp_path: Path):
    """Test que URLs con protocolo se preservan correctamente."""
    # Arrange
    credentials = [
        DecryptedCredential(
            domain="http://oldsite.com",
            username="user",
            password="pass",
            notes="",
            title="",
        )
    ]
    output_file = tmp_path / "test.csv"

    # Act
    export_to_protonpass(credentials, output_file)

    # Assert
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # No debe duplicar el protocolo
    assert rows[0]["url"] == "http://oldsite.com"
