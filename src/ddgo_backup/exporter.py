"""
exporter.py - Exportación de credenciales a diferentes formatos

Autor: Homero Thompson del Lago del Terror
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
    Exporta credenciales a un archivo CSV.

    Formato: name,url,username,password,notes,title

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_passwords_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a {output_path}")

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

    logger.success(f"Exportadas {len(credentials)} credenciales a {output_path}")
    return output_path


def export_to_json(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales a un archivo JSON.

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_passwords_{timestamp}.json")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a {output_path}")

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

    logger.success(f"Exportadas {len(credentials)} credenciales a {output_path}")
    return output_path


def export_to_bitwarden(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato compatible con Bitwarden.

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_bitwarden_{timestamp}.json")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato Bitwarden")

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
        f"Exportadas {len(credentials)} credenciales en formato Bitwarden a {output_path}"
    )
    return output_path


def export_to_protonpass(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato CSV compatible con ProtonPass.

    Formato ProtonPass: name,url,username,password,note,totp

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_protonpass_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato ProtonPass")

    fieldnames = ["name", "url", "username", "password", "note", "totp"]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for cred in credentials:
            # ProtonPass espera URL completa con https://
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
                    "totp": "",  # DuckDuckGo no guarda TOTP
                }
            )

    logger.success(
        f"Exportadas {len(credentials)} credenciales en formato ProtonPass a {output_path}"
    )
    return output_path


def export_to_1password(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato CSV compatible con 1Password.

    Formato: title,website,username,password,notes

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_1password_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato 1Password")

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
        f"Exportadas {len(credentials)} credenciales en formato 1Password a {output_path}"
    )
    return output_path


def export_to_nordpass(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato CSV compatible con NordPass.

    Formato NordPass: name,url,username,password,note

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_nordpass_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato NordPass")

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
        f"Exportadas {len(credentials)} credenciales en formato NordPass a {output_path}"
    )
    return output_path


def export_to_roboform(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato CSV compatible con RoboForm.

    Formato RoboForm: Name,Url,MatchUrl,Login,Pwd,Note

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_roboform_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato RoboForm")

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
                    "MatchUrl": url,  # RoboForm usa esto para matching
                    "Login": cred.username or "",
                    "Pwd": cred.password or "",
                    "Note": cred.notes or "",
                }
            )

    logger.success(
        f"Exportadas {len(credentials)} credenciales en formato RoboForm a {output_path}"
    )
    return output_path


def export_to_keeper(
    credentials: list[DecryptedCredential],
    output_path: Path | str | None = None,
) -> Path:
    """
    Exporta credenciales en formato CSV compatible con Keeper.

    Formato Keeper: Folder,Title,Login,Password,Website Address,Notes

    Args:
        credentials: Lista de credenciales descifradas
        output_path: Ruta del archivo de salida (opcional)

    Returns:
        Path: Ruta del archivo generado
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"ddg_keeper_{timestamp}.csv")
    else:
        output_path = Path(output_path)

    logger.info(f"Exportando {len(credentials)} credenciales a formato Keeper")

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
                    "Folder": "DuckDuckGo Import",  # Carpeta por defecto
                    "Title": cred.title or cred.domain or "",
                    "Login": cred.username or "",
                    "Password": cred.password or "",
                    "Website Address": url,
                    "Notes": cred.notes or "",
                }
            )

    logger.success(
        f"Exportadas {len(credentials)} credenciales en formato Keeper a {output_path}"
    )
    return output_path
