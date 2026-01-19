"""
exporter.py - Export credentials to different formats

Author: Homero Thompson del Lago del Terror
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from loguru import logger

from .models import DecryptedCredential


def export_to_csv(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials to a CSV file.

    Format: name,url,username,password,notes,title

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_passwords_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to {output_path}")

    fieldnames = ["name", "url", "username", "password", "notes", "title"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            writer.writerow(
                {
                    "name": cred.domain or "",
                    "url": cred.domain or "",
                    "username": cred.username or "",
                    "password": cred.password or "",
                    "notes": cred.notes or "",
                    "title": cred.title or "",
                }
            )

    logger.success(f"Exported {len(credentials)} credentials to {output_path}")
    return output_path


def export_to_json(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials to a JSON file.

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_passwords_{timestamp}.json")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to {output_path}")

    data = {
        "exported_at": datetime.now().isoformat(),
        "total_credentials": len(credentials),
        "credentials": [
            {
                "site": c.domain,
                "username": c.username,
                "password": c.password,
                "notes": c.notes,
                "title": c.title,
            }
            for c in credentials
        ],
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.success(f"Exported {len(credentials)} credentials to {output_path}")
    return output_path


def export_to_bitwarden(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in Bitwarden-compatible format.

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_bitwarden_{timestamp}.json")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to Bitwarden format")

    items = []
    for cred in credentials:
        item = {
            "type": 1,  # Login type
            "name": cred.title or cred.domain,
            "notes": cred.notes,
            "login": {
                "uris": [{"uri": f"https://{cred.domain}"}] if cred.domain else [],
                "username": cred.username,
                "password": cred.password,
            },
        }
        items.append(item)

    data = {
        "encrypted": False,
        "items": items,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.success(
        f"Exported {len(credentials)} credentials in Bitwarden format to {output_path}"
    )
    return output_path


def export_to_protonpass(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in ProtonPass-compatible CSV format.

    Format: name,url,username,password,note,totp

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_protonpass_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to ProtonPass format")

    fieldnames = ["name", "url", "username", "password", "note", "totp"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            # ProtonPass expects full URL with https://
            url = cred.domain or ""
            if url and not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            writer.writerow(
                {
                    "name": cred.title or cred.domain or "",
                    "url": url,
                    "username": cred.username or "",
                    "password": cred.password or "",
                    "note": cred.notes or "",
                    "totp": "",  # DuckDuckGo doesn't store TOTP
                }
            )

    logger.success(
        f"Exported {len(credentials)} credentials in ProtonPass format to {output_path}"
    )
    return output_path


def export_to_1password(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in 1Password-compatible CSV format.

    Format: title,website,username,password,notes

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_1password_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to 1Password format")

    fieldnames = ["title", "website", "username", "password", "notes"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            writer.writerow(
                {
                    "title": cred.title or cred.domain,
                    "website": f"https://{cred.domain}" if cred.domain else "",
                    "username": cred.username or "",
                    "password": cred.password or "",
                    "notes": cred.notes or "",
                }
            )

    logger.success(
        f"Exported {len(credentials)} credentials in 1Password format to {output_path}"
    )
    return output_path


def export_to_nordpass(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in NordPass-compatible CSV format.

    Format: name,url,username,password,note

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_nordpass_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to NordPass format")

    fieldnames = ["name", "url", "username", "password", "note"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            url = cred.domain or ""
            if url and not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            writer.writerow(
                {
                    "name": cred.title or cred.domain or "",
                    "url": url,
                    "username": cred.username or "",
                    "password": cred.password or "",
                    "note": cred.notes or "",
                }
            )

    logger.success(
        f"Exported {len(credentials)} credentials in NordPass format to {output_path}"
    )
    return output_path


def export_to_roboform(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in RoboForm-compatible CSV format.

    Format: Name,Url,MatchUrl,Login,Pwd,Note

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_roboform_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to RoboForm format")

    fieldnames = ["Name", "Url", "MatchUrl", "Login", "Pwd", "Note"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            url = cred.domain or ""
            if url and not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            writer.writerow(
                {
                    "Name": cred.title or cred.domain or "",
                    "Url": url,
                    "MatchUrl": url,  # RoboForm uses this for matching
                    "Login": cred.username or "",
                    "Pwd": cred.password or "",
                    "Note": cred.notes or "",
                }
            )

    logger.success(
        f"Exported {len(credentials)} credentials in RoboForm format to {output_path}"
    )
    return output_path


def export_to_keeper(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Export credentials in Keeper-compatible CSV format.

    Format: Folder,Title,Login,Password,Website Address,Notes

    Args:
        credentials: List of decrypted credentials
        output_path: Output file path (optional)

    Returns:
        Path: Path of the generated file
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_keeper_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exporting {len(credentials)} credentials to Keeper format")

    fieldnames = ["Folder", "Title", "Login", "Password", "Website Address", "Notes"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            url = cred.domain or ""
            if url and not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            writer.writerow(
                {
                    "Folder": "DuckDuckGo Import",  # Default folder
                    "Title": cred.title or cred.domain or "",
                    "Login": cred.username or "",
                    "Password": cred.password or "",
                    "Website Address": url,
                    "Notes": cred.notes or "",
                }
            )

    logger.success(
        f"Exported {len(credentials)} credentials in Keeper format to {output_path}"
    )
    return output_path
