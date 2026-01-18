#!/usr/bin/env python3
"""
main.py - CLI principal de DDG Backup

Autor: Homero Thompson del Lago del Terror

Uso:
    python -m ddgo_backup
    python -m ddgo_backup --format bitwarden
    python -m ddgo_backup --output passwords.csv
"""

import argparse
import sys
from pathlib import Path

from loguru import logger

from .api import SyncClient
from .crypto import decode_recovery_code, prepare_for_login
from .exporter import (
    export_to_1password,
    export_to_bitwarden,
    export_to_csv,
    export_to_json,
    export_to_keeper,
    export_to_nordpass,
    export_to_protonpass,
    export_to_roboform,
)


def setup_logging(verbose: bool = False):
    """Configura el logging."""
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    )


def get_recovery_code() -> str:
    """Solicita el recovery code al usuario."""
    print("\n" + "=" * 60)
    print("  DuckDuckGo Password Backup Tool")
    print("=" * 60)
    print("\nPara exportar tus contraseñas necesitas tu Recovery Code.")
    print("Lo puedes encontrar en: DDG App → Settings → Sync & Backup")
    print("\nEl código tiene este formato (JSON en Base64):")
    print('  {"recovery":{"primary_key":"...", "user_id":"..."}}')
    print("")
    print("┌" + "─" * 58 + "┐")
    print("│  💡 IMPORTANTE: El código del PDF viene en VARIAS LÍNEAS  │")
    print("│                                                          │")
    print("│  1. Pega TODO el código (puede ser 3-4 líneas)           │")
    print("│  2. Presiona ENTER                                       │")
    print("│  3. Presiona ENTER de nuevo (línea vacía) para continuar │")
    print("│                                                          │")
    print("│  >>> ENTER + ENTER (vacío) = CONTINUAR <<<               │")
    print("└" + "─" * 58 + "┘")
    print("")

    # Leer múltiples líneas hasta línea vacía
    # (el PDF de DDG divide el código en 3-4 líneas)
    print("Recovery Code (pega y luego ENTER vacío):")
    lines = []
    while True:
        try:
            line = input()
            if not line:  # Línea vacía = fin de entrada
                break
            lines.append(line)
        except EOFError:
            break

    code = "".join(lines)
    return code.strip()


def main():
    """Punto de entrada principal."""
    parser = argparse.ArgumentParser(
        description="Exporta contraseñas de DuckDuckGo a CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s                          # Exporta a CSV (formato por defecto)
  %(prog)s --format json            # Exporta a JSON
  %(prog)s --format bitwarden       # Formato compatible con Bitwarden
  %(prog)s --format 1password       # Formato compatible con 1Password
  %(prog)s -o passwords.csv         # Especifica archivo de salida
  %(prog)s --code "eyJyZWNvdmVyeSI..." # Pasa el recovery code directamente
        """,
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Archivo de salida (por defecto: ddg_passwords_TIMESTAMP.csv)",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "json", "bitwarden", "1password", "protonpass", "nordpass", "roboform", "keeper"],
        default="csv",
        help="Formato de exportación (default: csv)",
    )

    parser.add_argument(
        "--code",
        type=str,
        help="Recovery code (si no se especifica, se solicita interactivamente)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Mostrar información de depuración",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        # Obtener recovery code
        recovery_code = args.code or get_recovery_code()

        if not recovery_code:
            logger.error("Recovery code es requerido")
            sys.exit(1)

        # Decodificar recovery code
        logger.info("Decodificando recovery code...")
        primary_key, user_id = decode_recovery_code(recovery_code)
        logger.debug(f"User ID: {user_id[:8]}...")

        # Preparar claves para login
        logger.info("Derivando claves de autenticación...")
        login_keys = prepare_for_login(primary_key)

        # Conectar y obtener credenciales
        with SyncClient(user_id=user_id, login_keys=login_keys) as client:
            client.login()
            credentials = client.fetch_credentials()

        if not credentials:
            logger.warning("No se encontraron credenciales para exportar")
            sys.exit(0)

        # Exportar según formato
        exporters = {
            "csv": export_to_csv,
            "json": export_to_json,
            "bitwarden": export_to_bitwarden,
            "1password": export_to_1password,
            "protonpass": export_to_protonpass,
            "nordpass": export_to_nordpass,
            "roboform": export_to_roboform,
            "keeper": export_to_keeper,
        }

        exporter = exporters[args.format]
        output_path = exporter(credentials, args.output)

        print(f"\n✅ Exportación completada: {output_path}")
        print(f"   Total de credenciales: {len(credentials)}")
        print("\n⚠️  IMPORTANTE: Este archivo contiene tus contraseñas en texto plano.")
        print("   Guárdalo en un lugar seguro y elimínalo cuando ya no lo necesites.\n")

    except KeyboardInterrupt:
        print("\n\nOperación cancelada por el usuario.")
        sys.exit(130)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Error inesperado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
