"""
test_e2e.py - Tests de integración end-to-end

Autor: Homero Thompson del Lago del Terror

Tests que verifican el flujo completo de la aplicación:
Recovery Code → Crypto → API → Export
"""

import base64
import csv
import json
from pathlib import Path

import pytest

from ddgo_backup.crypto import (
    DecryptedCredential,
    decode_recovery_code,
    encrypt_data,
    prepare_for_login,
)
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


class TestEndToEndCryptoFlow:
    """Tests del flujo criptográfico completo."""

    def test_recovery_code_to_login_keys_flow(
        self, test_recovery_code: str, test_primary_key_b64: str, test_user_id: str
    ):
        """Test: Recovery code → decode → prepare_for_login → keys."""
        # Arrange - ya tenemos el recovery code del fixture

        # Act - Decodificar recovery code
        primary_key_b64, user_id = decode_recovery_code(test_recovery_code)

        # Assert - Valores correctos extraídos
        assert primary_key_b64 == test_primary_key_b64
        assert user_id == test_user_id

        # Act - Preparar claves para login
        login_keys = prepare_for_login(primary_key_b64)

        # Assert - Claves derivadas correctamente
        assert login_keys.password_hash is not None
        assert len(login_keys.password_hash) == 32
        assert login_keys.stretched_primary_key is not None
        assert len(login_keys.stretched_primary_key) == 32
        assert login_keys.primary_key is not None
        assert len(login_keys.primary_key) == 32

    def test_multiline_recovery_code_flow(
        self, test_recovery_code_multiline: str, test_user_id: str
    ):
        """Test: Recovery code multilínea (como del PDF) funciona correctamente."""
        # Arrange - Recovery code con saltos de línea

        # Act
        primary_key_b64, user_id = decode_recovery_code(test_recovery_code_multiline)

        # Assert
        assert user_id == test_user_id
        # Debe poder preparar login keys
        login_keys = prepare_for_login(primary_key_b64)
        assert login_keys.password_hash is not None

    def test_encrypt_decrypt_roundtrip_flow(self, test_secret_key: bytes):
        """Test: Datos cifrados pueden ser descifrados correctamente."""
        # Arrange
        test_data = [
            "simple_password",
            "contraseña_con_ñ",
            "パスワード",  # Japonés
            "🔐🔑💻",  # Emojis
            "",  # Vacío
            "a" * 1000,  # Largo
        ]

        for original in test_data:
            # Act
            encrypted = encrypt_data(original, test_secret_key)
            from ddgo_backup.crypto import decrypt_data

            decrypted = decrypt_data(encrypted, test_secret_key)

            # Assert
            assert decrypted == original, f"Fallo con: {original[:20]}..."


class TestEndToEndExportFlow:
    """Tests del flujo de exportación completo."""

    @pytest.fixture
    def credentials_list(self) -> list[DecryptedCredential]:
        """Lista de credenciales para tests E2E."""
        return [
            DecryptedCredential(
                domain="github.com",
                username="developer",
                password="gh_secret_123",
                notes="Personal GitHub",
                title="GitHub",
            ),
            DecryptedCredential(
                domain="google.com",
                username="user@gmail.com",
                password="google_pass_456",
                notes="Main email account",
                title="Google",
            ),
            DecryptedCredential(
                domain="amazon.com",
                username="shopper",
                password="shop_789",
                notes=None,
                title=None,
            ),
        ]

    def test_export_all_formats_creates_valid_files(
        self, credentials_list: list[DecryptedCredential], tmp_path: Path
    ):
        """Test: Todos los formatos de exportación crean archivos válidos."""
        # Arrange
        exporters = [
            ("csv", export_to_csv),
            ("json", export_to_json),
            ("bitwarden", export_to_bitwarden),
            ("1password", export_to_1password),
            ("protonpass", export_to_protonpass),
            ("nordpass", export_to_nordpass),
            ("roboform", export_to_roboform),
            ("keeper", export_to_keeper),
        ]

        for format_name, exporter in exporters:
            # Act
            output_file = (
                tmp_path
                / f"test_{format_name}.{'json' if format_name in ['json', 'bitwarden'] else 'csv'}"
            )
            result_path = exporter(credentials_list, output_file)

            # Assert
            assert result_path.exists(), f"{format_name}: Archivo no creado"
            assert result_path.stat().st_size > 0, f"{format_name}: Archivo vacío"

            # Verificar que el contenido es parseable
            content = result_path.read_text(encoding="utf-8")
            if format_name in ["json", "bitwarden"]:
                data = json.loads(content)
                assert data is not None, f"{format_name}: JSON inválido"
            else:
                # CSV - verificar que tiene headers y datos
                lines = content.strip().split("\n")
                assert len(lines) >= 2, f"{format_name}: CSV sin datos suficientes"

    def test_csv_contains_all_credentials(
        self, credentials_list: list[DecryptedCredential], tmp_path: Path
    ):
        """Test: CSV contiene todas las credenciales exportadas."""
        # Arrange
        output_file = tmp_path / "credentials.csv"

        # Act
        export_to_csv(credentials_list, output_file)

        # Assert
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["username"] == "developer"
        assert rows[1]["username"] == "user@gmail.com"
        assert rows[2]["username"] == "shopper"

    def test_bitwarden_format_is_importable(
        self, credentials_list: list[DecryptedCredential], tmp_path: Path
    ):
        """Test: Formato Bitwarden tiene estructura correcta para importación."""
        # Arrange
        output_file = tmp_path / "bitwarden.json"

        # Act
        export_to_bitwarden(credentials_list, output_file)

        # Assert
        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        # Verificar estructura Bitwarden
        assert "encrypted" in data
        assert data["encrypted"] is False
        assert "items" in data
        assert len(data["items"]) == 3

        # Verificar estructura de cada item
        for item in data["items"]:
            assert "type" in item
            assert item["type"] == 1  # Login type
            assert "name" in item
            assert "login" in item
            assert "uris" in item["login"]
            assert "username" in item["login"]
            assert "password" in item["login"]


class TestEndToEndFullPipeline:
    """Tests del pipeline completo: Recovery → API → Export."""

    def test_full_pipeline_with_mocked_api(
        self,
        test_recovery_code: str,
        test_secret_key: bytes,
        tmp_path: Path,
    ):
        """Test: Pipeline completo con API mockeada."""
        # Arrange - Crear credenciales cifradas
        credentials = [
            {"domain": "test.com", "username": "user1", "password": "pass1"},
            {"domain": "example.org", "username": "user2", "password": "pass2"},
        ]

        encrypted_entries = []
        for cred in credentials:
            encrypted_entries.append(
                {
                    "domain": encrypt_data(cred["domain"], test_secret_key),
                    "username": encrypt_data(cred["username"], test_secret_key),
                    "password": encrypt_data(cred["password"], test_secret_key),
                    "notes": encrypt_data("", test_secret_key),
                    "title": encrypt_data("", test_secret_key),
                }
            )

        # Mock de la respuesta de la API
        mock_credentials_response = {"credentials": {"entries": encrypted_entries}}

        # Act - Decodificar recovery code
        primary_key_b64, user_id = decode_recovery_code(test_recovery_code)
        login_keys = prepare_for_login(primary_key_b64)

        # Simular el descifrado de credenciales (como lo haría SyncClient)
        decrypted_credentials = []
        from ddgo_backup.crypto import decrypt_data

        for entry in encrypted_entries:
            decrypted_credentials.append(
                DecryptedCredential(
                    domain=decrypt_data(entry["domain"], test_secret_key),
                    username=decrypt_data(entry["username"], test_secret_key),
                    password=decrypt_data(entry["password"], test_secret_key),
                    notes=decrypt_data(entry["notes"], test_secret_key) or None,
                    title=decrypt_data(entry["title"], test_secret_key) or None,
                )
            )

        # Exportar a CSV
        output_file = tmp_path / "export.csv"
        export_to_csv(decrypted_credentials, output_file)

        # Assert - Verificar archivo exportado
        assert output_file.exists()
        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["name"] == "test.com"
        assert rows[0]["username"] == "user1"
        assert rows[0]["password"] == "pass1"
        assert rows[1]["name"] == "example.org"
        assert rows[1]["username"] == "user2"
        assert rows[1]["password"] == "pass2"

    def test_export_with_special_characters(self, tmp_path: Path):
        """Test: Exportación maneja caracteres especiales correctamente."""
        # Arrange
        credentials = [
            DecryptedCredential(
                domain="tëst.com",
                username="üser@emäil.com",
                password="pässwörd123!@#$%",
                notes="Nötäs con ñ y 日本語",
                title="Títülo",
            ),
        ]

        # Act
        output_file = tmp_path / "special.csv"
        export_to_csv(credentials, output_file)

        # Assert
        with open(output_file, encoding="utf-8") as f:
            content = f.read()

        assert "tëst.com" in content
        assert "üser@emäil.com" in content
        assert "pässwörd123!@#$%" in content
        assert "Nötäs con ñ y 日本語" in content

    def test_export_empty_credentials_list(self, tmp_path: Path):
        """Test: Exportación de lista vacía crea archivo con headers."""
        # Arrange
        credentials: list[DecryptedCredential] = []

        # Act
        output_file = tmp_path / "empty.csv"
        export_to_csv(credentials, output_file)

        # Assert
        assert output_file.exists()
        with open(output_file, encoding="utf-8") as f:
            content = f.read()
        # Debe tener al menos los headers
        assert "name" in content or "url" in content


class TestSecurityValidation:
    """Tests de validación de seguridad."""

    def test_different_nonces_produce_different_ciphertext(
        self, test_secret_key: bytes
    ):
        """Test: Cifrado usa nonces aleatorios (no determinístico)."""
        # Arrange
        plaintext = "same_password"

        # Act - Cifrar el mismo texto múltiples veces
        ciphertexts = set()
        for _ in range(10):
            encrypted = encrypt_data(plaintext, test_secret_key)
            ciphertexts.add(encrypted)

        # Assert - Todos los ciphertexts deben ser diferentes
        assert len(ciphertexts) == 10, "Cifrado no usa nonces aleatorios!"

    def test_wrong_key_cannot_decrypt(self, test_secret_key: bytes):
        """Test: Clave incorrecta no puede descifrar datos."""
        # Arrange
        plaintext = "secret_data"
        encrypted = encrypt_data(plaintext, test_secret_key)
        wrong_key = b"wrong_key_32_bytes_for_testing!!"

        # Act & Assert
        from ddgo_backup.crypto import decrypt_data

        with pytest.raises(ValueError, match="Error al descifrar"):
            decrypt_data(encrypted, wrong_key)

    def test_recovery_code_contains_required_fields(self):
        """Test: Recovery code inválido sin campos requeridos falla."""
        # Arrange - Recovery code sin user_id
        invalid_data = {"recovery": {"primary_key": "dGVzdA=="}}
        invalid_code = base64.b64encode(json.dumps(invalid_data).encode()).decode()

        # Act & Assert
        with pytest.raises(KeyError):
            decode_recovery_code(invalid_code)
