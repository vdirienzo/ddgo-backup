"""
test_main.py - Tests unitarios para CLI principal

Autor: Homero Thompson del Lago del Terror

Tests para:
- setup_logging(): configuración de loguru
- get_recovery_code(): input interactivo de usuario
- main(): punto de entrada CLI con diferentes argumentos
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from loguru import logger

from ddgo_backup.main import get_recovery_code, main, setup_logging


class TestSetupLogging:
    """Tests para configuración de logging."""

    def test_setup_logging_default_level(self):
        """Test que setup_logging configura nivel INFO por defecto."""
        # Arrange & Act
        setup_logging(verbose=False)

        # Assert - verificar que logger está configurado (no lanza excepciones)
        logger.info("Test message")

    def test_setup_logging_verbose_enables_debug(self):
        """Test que verbose=True habilita nivel DEBUG."""
        # Arrange & Act
        setup_logging(verbose=True)

        # Assert - verificar que logger está configurado para DEBUG
        logger.debug("Debug message")

    def test_setup_logging_removes_previous_handlers(self):
        """Test que setup_logging limpia handlers previos."""
        # Arrange
        setup_logging(verbose=False)
        initial_handler_count = len(logger._core.handlers)

        # Act - llamar nuevamente
        setup_logging(verbose=True)

        # Assert - debería remover handlers previos y agregar uno nuevo
        assert len(logger._core.handlers) == initial_handler_count


class TestGetRecoveryCode:
    """Tests para obtención de recovery code interactivo."""

    def test_get_recovery_code_single_line(self, monkeypatch):
        """Test que get_recovery_code lee una línea de input."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        inputs = iter([test_code, ""])  # Código + línea vacía para terminar
        monkeypatch.setattr("builtins.input", lambda: next(inputs))

        # Act
        result = get_recovery_code()

        # Assert
        assert result == test_code

    def test_get_recovery_code_multiple_lines(self, monkeypatch):
        """Test que get_recovery_code concatena múltiples líneas."""
        # Arrange
        line1 = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6"
        line2 = "InRlc3QiLCJ1c2VyX2lkIjoidGVzdC11c2Vy"
        line3 = "LWlkIn19"
        inputs = iter([line1, line2, line3, ""])  # 3 líneas + vacía
        monkeypatch.setattr("builtins.input", lambda: next(inputs))

        # Act
        result = get_recovery_code()

        # Assert
        expected = line1 + line2 + line3
        assert result == expected

    def test_get_recovery_code_strips_whitespace(self, monkeypatch):
        """Test que get_recovery_code elimina espacios al inicio/final."""
        # Arrange
        test_code = "  eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0=  "
        inputs = iter([test_code, ""])
        monkeypatch.setattr("builtins.input", lambda: next(inputs))

        # Act
        result = get_recovery_code()

        # Assert
        assert result == test_code.strip()

    def test_get_recovery_code_handles_eof(self, monkeypatch):
        """Test que get_recovery_code maneja EOFError."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="

        def mock_input():
            """Mock que lanza EOFError después de una línea."""
            if not hasattr(mock_input, "called"):
                mock_input.called = True
                return test_code
            raise EOFError

        monkeypatch.setattr("builtins.input", mock_input)

        # Act
        result = get_recovery_code()

        # Assert
        assert result == test_code


class TestMainCLI:
    """Tests para el punto de entrada CLI main()."""

    @pytest.fixture
    def mock_dependencies(self):
        """Fixture que mockea todas las dependencias de main()."""
        with (
            patch("ddgo_backup.main.decode_recovery_code") as mock_decode,
            patch("ddgo_backup.main.prepare_for_login") as mock_prepare,
            patch("ddgo_backup.main.SyncClient") as mock_client,
            patch("ddgo_backup.main.export_to_csv") as mock_csv,
            patch("ddgo_backup.main.export_to_json") as mock_json,
            patch("ddgo_backup.main.export_to_bitwarden") as mock_bitwarden,
            patch("ddgo_backup.main.export_to_1password") as mock_1password,
            patch("ddgo_backup.main.export_to_protonpass") as mock_protonpass,
            patch("ddgo_backup.main.export_to_nordpass") as mock_nordpass,
            patch("ddgo_backup.main.export_to_roboform") as mock_roboform,
            patch("ddgo_backup.main.export_to_keeper") as mock_keeper,
        ):
            # Configurar comportamiento de mocks
            mock_decode.return_value = ("primary_key_test", "user_id_test")
            mock_prepare.return_value = {"key": "value"}

            # Mock del cliente
            mock_client_instance = MagicMock()
            mock_client_instance.__enter__ = Mock(return_value=mock_client_instance)
            mock_client_instance.__exit__ = Mock(return_value=False)
            mock_client_instance.fetch_credentials.return_value = [
                {"domain": "example.com", "username": "test", "password": "pass"}
            ]
            mock_client.return_value = mock_client_instance

            # Mock de exporters retornan Path
            mock_csv.return_value = Path("/tmp/export.csv")
            mock_json.return_value = Path("/tmp/export.json")
            mock_bitwarden.return_value = Path("/tmp/export.csv")
            mock_1password.return_value = Path("/tmp/export.csv")
            mock_protonpass.return_value = Path("/tmp/export.csv")
            mock_nordpass.return_value = Path("/tmp/export.csv")
            mock_roboform.return_value = Path("/tmp/export.csv")
            mock_keeper.return_value = Path("/tmp/export.csv")

            yield {
                "decode": mock_decode,
                "prepare": mock_prepare,
                "client": mock_client,
                "csv": mock_csv,
                "json": mock_json,
                "bitwarden": mock_bitwarden,
                "1password": mock_1password,
                "protonpass": mock_protonpass,
                "nordpass": mock_nordpass,
                "roboform": mock_roboform,
                "keeper": mock_keeper,
            }

    def test_main_with_code_argument_default_format(
        self, monkeypatch, mock_dependencies
    ):
        """Test main() con --code y formato CSV por defecto."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])

        # Act
        main()

        # Assert
        mock_dependencies["decode"].assert_called_once_with(test_code)
        mock_dependencies["csv"].assert_called_once()

    def test_main_with_json_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato JSON."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys, "argv", ["ddgo_backup", "--code", test_code, "--format", "json"]
        )

        # Act
        main()

        # Assert
        mock_dependencies["json"].assert_called_once()
        mock_dependencies["csv"].assert_not_called()

    def test_main_with_bitwarden_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato Bitwarden."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys,
            "argv",
            ["ddgo_backup", "--code", test_code, "--format", "bitwarden"],
        )

        # Act
        main()

        # Assert
        mock_dependencies["bitwarden"].assert_called_once()

    def test_main_with_1password_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato 1Password."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys,
            "argv",
            ["ddgo_backup", "--code", test_code, "--format", "1password"],
        )

        # Act
        main()

        # Assert
        mock_dependencies["1password"].assert_called_once()

    def test_main_with_protonpass_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato ProtonPass."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys,
            "argv",
            ["ddgo_backup", "--code", test_code, "--format", "protonpass"],
        )

        # Act
        main()

        # Assert
        mock_dependencies["protonpass"].assert_called_once()

    def test_main_with_nordpass_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato NordPass."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys,
            "argv",
            ["ddgo_backup", "--code", test_code, "--format", "nordpass"],
        )

        # Act
        main()

        # Assert
        mock_dependencies["nordpass"].assert_called_once()

    def test_main_with_roboform_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato RoboForm."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys,
            "argv",
            ["ddgo_backup", "--code", test_code, "--format", "roboform"],
        )

        # Act
        main()

        # Assert
        mock_dependencies["roboform"].assert_called_once()

    def test_main_with_keeper_format(self, monkeypatch, mock_dependencies):
        """Test main() con formato Keeper."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys, "argv", ["ddgo_backup", "--code", test_code, "--format", "keeper"]
        )

        # Act
        main()

        # Assert
        mock_dependencies["keeper"].assert_called_once()

    def test_main_with_output_argument(self, monkeypatch, mock_dependencies):
        """Test main() con argumento --output personalizado."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        output_file = "/tmp/my_passwords.csv"
        monkeypatch.setattr(
            sys, "argv", ["ddgo_backup", "--code", test_code, "--output", output_file]
        )

        # Act
        main()

        # Assert
        args, kwargs = mock_dependencies["csv"].call_args
        # Verificar que se pasó el output path
        assert args[1] == Path(output_file) or kwargs.get("output_path") == Path(
            output_file
        )

    def test_main_with_verbose_flag(self, monkeypatch, mock_dependencies):
        """Test main() con flag --verbose."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(
            sys, "argv", ["ddgo_backup", "--code", test_code, "--verbose"]
        )

        # Act
        with patch("ddgo_backup.main.setup_logging") as mock_setup:
            main()

            # Assert
            mock_setup.assert_called_once_with(True)

    def test_main_without_code_prompts_user(self, monkeypatch, mock_dependencies):
        """Test main() sin --code solicita input interactivo."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup"])

        with patch("ddgo_backup.main.get_recovery_code") as mock_get_code:
            mock_get_code.return_value = test_code

            # Act
            main()

            # Assert
            mock_get_code.assert_called_once()
            mock_dependencies["decode"].assert_called_once_with(test_code)

    def test_main_exits_when_code_is_empty(self, monkeypatch, mock_dependencies):
        """Test main() sale con error si el código está vacío."""
        # Arrange
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", ""])

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_main_exits_on_value_error(self, monkeypatch, mock_dependencies):
        """Test main() sale con error 1 en ValueError."""
        # Arrange
        test_code = "invalid_code"
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])
        mock_dependencies["decode"].side_effect = ValueError("Invalid recovery code")

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_main_exits_on_keyboard_interrupt(self, monkeypatch, mock_dependencies):
        """Test main() sale con código 130 en KeyboardInterrupt."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])
        mock_dependencies["decode"].side_effect = KeyboardInterrupt()

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 130

    def test_main_exits_on_unexpected_exception(self, monkeypatch, mock_dependencies):
        """Test main() sale con error 1 en excepciones inesperadas."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])
        mock_dependencies["decode"].side_effect = RuntimeError("Unexpected error")

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    def test_main_exits_gracefully_when_no_credentials_found(
        self, monkeypatch, mock_dependencies
    ):
        """Test main() sale con código 0 si no hay credenciales."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])

        # Configurar cliente para retornar lista vacía
        mock_client_instance = mock_dependencies["client"].return_value
        mock_client_instance.__enter__.return_value.fetch_credentials.return_value = []

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0

    def test_main_calls_sync_client_correctly(self, monkeypatch, mock_dependencies):
        """Test main() llama a SyncClient con los parámetros correctos."""
        # Arrange
        test_code = "eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6InRlc3QifX0="
        monkeypatch.setattr(sys, "argv", ["ddgo_backup", "--code", test_code])

        # Act
        main()

        # Assert
        mock_dependencies["client"].assert_called_once_with(
            user_id="user_id_test", login_keys={"key": "value"}
        )
        mock_client_instance = mock_dependencies["client"].return_value.__enter__()
        mock_client_instance.login.assert_called_once()
        mock_client_instance.fetch_credentials.assert_called_once()
