#!/usr/bin/env python3
"""
main.py - Main CLI for DDG Backup

Author: Homero Thompson del Lago del Terror

Usage:
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
    """Configure logging."""
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    )


def get_recovery_code() -> str:
    """Request the recovery code from the user."""
    print("\n" + "=" * 60)
    print("  DuckDuckGo Password Backup Tool")
    print("=" * 60)
    print("\nTo export your passwords you need your Recovery Code.")
    print("You can find it in: DDG App -> Settings -> Sync & Backup")
    print("")
    print("+" + "-" * 61 + "+")
    print("|  IMPORTANT: The code from the PDF comes in MULTIPLE LINES   |")
    print("|                                                             |")
    print("|  1. Paste the ENTIRE code (can be 3-4 lines)                |")
    print("|  2. Press ENTER                                             |")
    print("|  3. Press ENTER again (empty line) to continue              |")
    print("+" + "-" * 61 + "+")
    print("")

    # Read multiple lines until empty line
    # (DDG PDF splits the code into 3-4 lines)
    print("Recovery Code (paste then empty ENTER):")
    lines = []
    while True:
        try:
            line = input()
            if not line:  # Empty line = end of input
                break
            lines.append(line)
        except EOFError:
            break

    code = "".join(lines)
    return code.strip()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Export DuckDuckGo passwords to CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Export to CSV (default format)
  %(prog)s --format json            # Export to JSON
  %(prog)s --format bitwarden       # Bitwarden-compatible format
  %(prog)s --format 1password       # 1Password-compatible format
  %(prog)s -o passwords.csv         # Specify output file
  %(prog)s --code "eyJyZWNvdmVyeSI..." # Pass recovery code directly
        """,
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file (default: ddg_passwords_TIMESTAMP.csv)",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=[
            "csv",
            "json",
            "bitwarden",
            "1password",
            "protonpass",
            "nordpass",
            "roboform",
            "keeper",
        ],
        default="csv",
        help="Export format (default: csv)",
    )

    parser.add_argument(
        "--code",
        type=str,
        help="Recovery code (if not specified, will be requested interactively)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug information",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        # Get recovery code
        recovery_code = args.code or get_recovery_code()

        if not recovery_code:
            logger.error("Recovery code is required")
            sys.exit(1)

        # Decode recovery code
        logger.info("Decoding recovery code...")
        primary_key, user_id = decode_recovery_code(recovery_code)
        logger.debug(f"User ID: {user_id[:8]}...")

        # Prepare keys for login
        logger.info("Deriving authentication keys...")
        login_keys = prepare_for_login(primary_key)

        # Connect and get credentials
        with SyncClient(user_id=user_id, login_keys=login_keys) as client:
            client.login()
            credentials = client.fetch_credentials()

        if not credentials:
            logger.warning("No credentials found to export")
            sys.exit(0)

        # Export according to format
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

        print(f"\n[OK] Export completed: {output_path}")
        print(f"   Total credentials: {len(credentials)}")
        print("\n[!] IMPORTANT: This file contains your passwords in plain text.")
        print("   Store it in a safe place and delete it when no longer needed.\n")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(130)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
