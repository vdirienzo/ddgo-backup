<div align="center">

```
    ____  ____  ______   ____             __
   / __ \/ __ \/ ____/  / __ )____ ______/ /____  ______
  / / / / / / / / __   / __  / __ `/ ___/ //_/ / / / __ \
 / /_/ / /_/ / /_/ /  / /_/ / /_/ / /__/ ,< / /_/ / /_/ /
/_____/_____/\____/  /_____/\__,_/\___/_/|_|\__,_/ .___/
                                                /_/
```

# DDG Backup

### Herramienta de Exportación de Contraseñas de DuckDuckGo

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Exporta tus contraseñas guardadas en DuckDuckGo Android a CSV y otros formatos de password managers populares.**

[Características](#-características) •
[Instalación](#-instalación) •
[Obtener Recovery Code](#-cómo-obtener-tu-recovery-code) •
[Uso](#-uso) •
[Formatos](#-formatos-de-exportación)

</div>

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Cómo Obtener tu Recovery Code](#-cómo-obtener-tu-recovery-code)
- [Uso](#-uso)
- [Formatos de Exportación](#-formatos-de-exportación)
- [Arquitectura Técnica](#-arquitectura-técnica)
- [Seguridad](#-seguridad)
- [Solución de Problemas](#-solución-de-problemas)
- [Changelog](#-changelog)
- [Autor](#-autor)
- [Licencia](#-licencia)

---

## 📖 Descripción

**DDG Backup** es una herramienta de línea de comandos que permite exportar las contraseñas guardadas en la aplicación DuckDuckGo para Android.

DuckDuckGo no ofrece una función nativa de exportación de contraseñas, lo que puede ser problemático si deseas:

- 🔄 Migrar a otro gestor de contraseñas
- 💾 Crear un backup de seguridad de tus credenciales
- 🔍 Auditar qué contraseñas tienes guardadas

Esta herramienta utiliza el **Recovery Code** oficial de DuckDuckGo y la API de sincronización para obtener tus credenciales de forma segura, descifrándolas localmente en tu computadora.

---

## ✨ Características

| Característica | Descripción |
|----------------|-------------|
| 🔐 **Seguro** | Descifrado local - tus contraseñas nunca viajan en texto plano |
| 📱 **Sin Root** | No requiere root ni acceso especial a tu dispositivo Android |
| 📤 **Multi-formato** | Exporta a 8 formatos diferentes de password managers |
| 🔑 **Oficial** | Usa el Recovery Code oficial de DuckDuckGo |
| 🐍 **Python Moderno** | Escrito en Python 3.11+ con tipado estático |
| ⚡ **Rápido** | Exporta cientos de contraseñas en segundos |

### Formatos Soportados

- ✅ CSV (genérico)
- ✅ JSON
- ✅ Bitwarden
- ✅ 1Password
- ✅ ProtonPass
- ✅ NordPass
- ✅ RoboForm
- ✅ Keeper

---

## 📋 Requisitos

- **Python 3.11** o superior
- **uv** (recomendado) o pip
- Tu **Recovery Code** de DuckDuckGo Android

### Dependencias

| Paquete | Versión | Propósito |
|---------|---------|-----------|
| `pynacl` | ≥1.6.2 | Criptografía (libsodium) |
| `httpx` | ≥0.28.1 | Cliente HTTP async |
| `pydantic` | ≥2.12.5 | Validación de datos |
| `loguru` | ≥0.7.3 | Logging |

---

## 🚀 Instalación

### Opción 1: Con uv (Recomendado)

```bash
# Clonar el repositorio
git clone https://github.com/user/ddgo-backup.git
cd ddgo-backup

# Instalar dependencias con uv
uv sync

# Verificar instalación
uv run python -m ddgo_backup --help
```

### Opción 2: Con pip

```bash
# Clonar el repositorio
git clone https://github.com/user/ddgo-backup.git
cd ddgo-backup

# Crear entorno virtual
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Instalar
pip install -e .

# Verificar instalación
ddgo-backup --help
```

### Opción 3: Script de ejecución rápida

```bash
# Crear script de ejecución
cat > run.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
uv run python -m ddgo_backup "$@"
EOF
chmod +x run.sh

# Ejecutar
./run.sh
```

---

## 📱 Cómo Obtener tu Recovery Code

El Recovery Code es la clave maestra que permite acceder a tus contraseñas sincronizadas. DuckDuckGo lo genera cuando activas la función de Sync & Backup.

### Paso 1: Abrir DuckDuckGo en tu Android

<table>
<tr>
<td width="50%">

1. Abre la app **DuckDuckGo** en tu teléfono Android
2. Toca el menú **⋮** (tres puntos verticales)
3. Selecciona **Settings** (Configuración)

</td>
<td width="50%">

```
┌─────────────────────────┐
│  DuckDuckGo Browser     │
│  ─────────────────────  │
│                         │
│  [⋮] ← Toca aquí        │
│    │                    │
│    ├─ Bookmarks         │
│    ├─ Downloads         │
│    └─ Settings ← Aquí   │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Paso 2: Acceder a Sync & Backup

<table>
<tr>
<td width="50%">

4. Dentro de Settings, busca y toca **Sync & Backup**
5. Si no tienes sync activado, actívalo primero

</td>
<td width="50%">

```
┌─────────────────────────┐
│  ⚙️ Settings            │
│  ─────────────────────  │
│                         │
│  General                │
│  Appearance             │
│  Privacy                │
│  ─────────────────────  │
│  🔄 Sync & Backup ← Aquí│
│  ─────────────────────  │
│  About                  │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Paso 3: Obtener el Recovery Code

<table>
<tr>
<td width="50%">

6. Toca **Recovery Code** o **Save Recovery PDF**
7. Se mostrará tu código o se descargará un PDF

</td>
<td width="50%">

```
┌─────────────────────────┐
│  🔄 Sync & Backup       │
│  ─────────────────────  │
│                         │
│  Status: ✅ Synced      │
│  Devices: 2             │
│                         │
│  ─────────────────────  │
│  📋 Recovery Code ← Aquí│
│  📄 Save Recovery PDF   │
│  ─────────────────────  │
│                         │
└─────────────────────────┘
```

</td>
</tr>
</table>

### Paso 4: Copiar el código

El Recovery Code tiene este formato (JSON codificado en Base64):

```
eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6IkVKRU1QTE
9fRkFMU09fTk9fVVNBUl9FU1RPX0VTX1VOQV9ERUIP
U1RSQUNJT04iLCJ1c2VyX2lkIjoiMDAwMDAwMDAtMDAw
MC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn19
```

> ⚠️ **NOTA**: El PDF divide el código en varias líneas. **DDG Backup acepta el código con saltos de línea** - no necesitas juntarlo manualmente.

---

## 💻 Uso

### Modo Interactivo (Recomendado)

```bash
uv run python -m ddgo_backup
```

```
============================================================
  DuckDuckGo Password Backup Tool
============================================================

Para exportar tus contraseñas necesitas tu Recovery Code.
Lo puedes encontrar en: DDG App → Settings → Sync & Backup

💡 IMPORTANTE: Si el código viene en varias líneas (como en el PDF),
   pégalo todo y presiona ENTER dos veces cuando termines.

Recovery Code (pega todo, luego ENTER vacío para continuar):
eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleS...
...resto del código...
...última línea==
                                              ← ENTER vacío

20:19:43 | INFO     | Decodificando recovery code...
20:19:43 | INFO     | Derivando claves de autenticación...
20:19:44 | SUCCESS  | Login exitoso. 2 dispositivo(s) en la cuenta.
20:19:45 | SUCCESS  | Descifradas 104 credenciales exitosamente

✅ Exportación completada: ddg_passwords_20260118_201945.csv
   Total de credenciales: 104
```

### Modo Directo (con código en línea de comandos)

```bash
# Exportar a CSV (formato por defecto)
uv run python -m ddgo_backup --code "TU_RECOVERY_CODE"

# Especificar archivo de salida
uv run python -m ddgo_backup --code "TU_RECOVERY_CODE" -o mis_passwords.csv

# Exportar a formato específico
uv run python -m ddgo_backup --code "TU_RECOVERY_CODE" --format bitwarden

# Modo verbose (más información)
uv run python -m ddgo_backup --code "TU_RECOVERY_CODE" -v
```

### Opciones de Línea de Comandos

| Opción | Corto | Descripción | Valor por defecto |
|--------|-------|-------------|-------------------|
| `--code` | | Recovery Code de DuckDuckGo | (interactivo) |
| `--output` | `-o` | Archivo de salida | `ddg_passwords_TIMESTAMP.csv` |
| `--format` | `-f` | Formato de exportación | `csv` |
| `--verbose` | `-v` | Mostrar información detallada | `false` |
| `--help` | `-h` | Mostrar ayuda | |

---

## 📦 Formatos de Exportación

### CSV Genérico

```bash
uv run python -m ddgo_backup --format csv
```

| Columna | Descripción |
|---------|-------------|
| `name` | Dominio del sitio |
| `url` | URL del sitio |
| `username` | Nombre de usuario |
| `password` | Contraseña |
| `notes` | Notas adicionales |
| `title` | Título del sitio |

```csv
"name","url","username","password","notes","title"
"github.com","github.com","usuario","contraseña123","","GitHub"
```

---

### JSON

```bash
uv run python -m ddgo_backup --format json
```

```json
{
  "exported_at": "2026-01-18T20:30:00",
  "total_credentials": 104,
  "credentials": [
    {
      "site": "github.com",
      "username": "usuario",
      "password": "contraseña123",
      "notes": null,
      "title": "GitHub"
    }
  ]
}
```

---

### Bitwarden

```bash
uv run python -m ddgo_backup --format bitwarden -o bitwarden_import.json
```

Formato JSON compatible con la importación de Bitwarden:

```json
{
  "encrypted": false,
  "items": [
    {
      "type": 1,
      "name": "GitHub",
      "notes": null,
      "login": {
        "uris": [{"uri": "https://github.com"}],
        "username": "usuario",
        "password": "contraseña123"
      }
    }
  ]
}
```

**Cómo importar en Bitwarden:**
1. Abre Bitwarden Web Vault
2. Ve a Tools → Import Data
3. Selecciona "Bitwarden (json)"
4. Sube el archivo generado

---

### 1Password

```bash
uv run python -m ddgo_backup --format 1password -o 1password_import.csv
```

| Columna | Descripción |
|---------|-------------|
| `title` | Título del item |
| `website` | URL completa |
| `username` | Usuario |
| `password` | Contraseña |
| `notes` | Notas |

**Cómo importar en 1Password:**
1. Abre 1Password
2. Ve a File → Import → CSV
3. Selecciona el archivo generado

---

### ProtonPass

```bash
uv run python -m ddgo_backup --format protonpass -o protonpass_import.csv
```

| Columna | Descripción |
|---------|-------------|
| `name` | Nombre del item |
| `url` | URL completa con https:// |
| `username` | Usuario |
| `password` | Contraseña |
| `note` | Notas |
| `totp` | Código 2FA (vacío) |

**Cómo importar en ProtonPass:**
1. Abre ProtonPass
2. Ve a Settings → Import
3. Selecciona "Import from CSV"
4. Sube el archivo generado

---

### NordPass

```bash
uv run python -m ddgo_backup --format nordpass -o nordpass_import.csv
```

| Columna | Descripción |
|---------|-------------|
| `name` | Nombre del item |
| `url` | URL completa |
| `username` | Usuario |
| `password` | Contraseña |
| `note` | Notas |

**Cómo importar en NordPass:**
1. Abre NordPass
2. Ve a Settings → Import Items
3. Selecciona "CSV file"
4. Sube el archivo generado

---

### RoboForm

```bash
uv run python -m ddgo_backup --format roboform -o roboform_import.csv
```

| Columna | Descripción |
|---------|-------------|
| `Name` | Nombre del item |
| `Url` | URL del sitio |
| `MatchUrl` | URL para matching |
| `Login` | Usuario |
| `Pwd` | Contraseña |
| `Note` | Notas |

**Cómo importar en RoboForm:**
1. Abre RoboForm
2. Ve a RoboForm → Import
3. Selecciona "CSV File"
4. Sube el archivo generado

---

### Keeper

```bash
uv run python -m ddgo_backup --format keeper -o keeper_import.csv
```

| Columna | Descripción |
|---------|-------------|
| `Folder` | Carpeta destino |
| `Title` | Título del item |
| `Login` | Usuario |
| `Password` | Contraseña |
| `Website Address` | URL completa |
| `Notes` | Notas |

**Cómo importar en Keeper:**
1. Abre Keeper Web Vault
2. Ve a Settings → Import
3. Selecciona "CSV File"
4. Sube el archivo generado

> 📁 Todas las contraseñas se importan en la carpeta "DuckDuckGo Import"

---

## 🔧 Arquitectura Técnica

### Flujo de Datos

```
┌─────────────────────────────────────────────────────────────────────┐
│                     RECOVERY CODE (del PDF)                         │
│         eyJyZWNvdmVyeSI6eyJwcmltYXJ5X2tleSI6Ii4uLiJ9fQ==           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    1. DECODIFICAR BASE64                            │
│   {"recovery": {"primary_key": "xxx", "user_id": "yyy"}}           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 2. DERIVAR CLAVES (BLAKE2b KDF)                     │
│                                                                     │
│   primary_key ──┬──► password_hash (context: "Password")           │
│                 └──► stretched_primary_key (context: "Stretchy")   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    3. LOGIN EN API DE SYNC                          │
│                                                                     │
│   POST https://sync.duckduckgo.com/sync/login                      │
│   Body: {user_id, hashed_password, device_id, device_name}         │
│                                                                     │
│   Response: {token, protected_encryption_key, devices[]}           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              4. DESCIFRAR SECRET KEY (XSalsa20-Poly1305)           │
│                                                                     │
│   protected_encryption_key + stretched_primary_key                 │
│                         │                                           │
│                         ▼                                           │
│                    secret_key (32 bytes)                           │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  5. OBTENER CREDENCIALES CIFRADAS                   │
│                                                                     │
│   GET https://sync.duckduckgo.com/sync/credentials                 │
│   Header: Authorization: Bearer {token}                            │
│                                                                     │
│   Response: {credentials: [{domain, username, password, ...}]}     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│            6. DESCIFRAR CADA CAMPO (XSalsa20-Poly1305)             │
│                                                                     │
│   Para cada credencial:                                            │
│     domain   = decrypt(encrypted_domain, secret_key)               │
│     username = decrypt(encrypted_username, secret_key)             │
│     password = decrypt(encrypted_password, secret_key)             │
│     notes    = decrypt(encrypted_notes, secret_key)                │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      7. EXPORTAR A ARCHIVO                          │
│                                                                     │
│   CSV / JSON / Bitwarden / 1Password / ProtonPass / etc.           │
└─────────────────────────────────────────────────────────────────────┘
```

### Algoritmos Criptográficos

| Operación | Algoritmo | Librería |
|-----------|-----------|----------|
| Derivación de claves | BLAKE2b con salt/personal | PyNaCl |
| Cifrado simétrico | XSalsa20-Poly1305 | PyNaCl |
| Formato de nonce | 24 bytes al final del ciphertext | - |

### Estructura del Proyecto

```
ddgo-backup/
├── src/
│   └── ddgo_backup/
│       ├── __init__.py      # Metadata del paquete
│       ├── __main__.py      # Entry point para python -m
│       ├── main.py          # CLI con argparse
│       ├── crypto.py        # Criptografía (KDF, XSalsa20)
│       ├── api.py           # Cliente HTTP para sync API
│       ├── models.py        # Modelos Pydantic
│       └── exporter.py      # Exportadores (CSV, JSON, etc.)
├── pyproject.toml           # Configuración del proyecto
├── README.md                # Esta documentación
└── run.sh                   # Script de ejecución rápida
```

---

## 🔒 Seguridad

### ✅ Lo que esta herramienta hace bien

| Aspecto | Implementación |
|---------|----------------|
| **Descifrado local** | Tus contraseñas se descifran en tu computadora, no en ningún servidor |
| **Sin almacenamiento** | La herramienta no guarda tu Recovery Code ni credenciales |
| **Criptografía estándar** | Usa PyNaCl (bindings de libsodium), la misma librería que usa DuckDuckGo |
| **Código abierto** | Puedes auditar exactamente qué hace el código |

### ⚠️ Advertencias de seguridad

| Riesgo | Mitigación |
|--------|------------|
| **El archivo exportado contiene contraseñas en texto plano** | Elimínalo inmediatamente después de importar a tu nuevo gestor |
| **El Recovery Code es tu clave maestra** | No lo compartas con nadie. Considera regenerarlo después de usar esta herramienta |
| **El código se muestra en pantalla** | Usa `--code` en lugar del modo interactivo si te preocupa |

### 🔐 Buenas prácticas

```bash
# 1. Exportar las contraseñas
uv run python -m ddgo_backup -o passwords.csv

# 2. Importar al nuevo gestor de contraseñas
# (sigue las instrucciones del gestor)

# 3. ELIMINAR el archivo inmediatamente
rm passwords.csv

# 4. Verificar que se eliminó
ls -la passwords.csv  # Debe dar error "No such file"
```

---

## ❓ Solución de Problemas

### Error: "Recovery code inválido"

**Causa**: El código no se copió completamente o tiene caracteres extra.

**Solución**:
1. Asegúrate de copiar TODO el código del PDF
2. El código puede tener 3-4 líneas, eso está bien
3. Presiona ENTER en una línea vacía después de pegar

```bash
# Prueba con modo verbose para más información
uv run python -m ddgo_backup -v
```

### Error: "Error de login: 401"

**Causa**: Credenciales inválidas.

**Solución**:
1. Verifica que el Recovery Code sea correcto
2. Asegúrate de que tu cuenta de Sync esté activa en el teléfono
3. Intenta regenerar el Recovery Code desde la app

### Error: "Connection refused" o timeout

**Causa**: Problema de red o servidor.

**Solución**:
1. Verifica tu conexión a internet
2. Intenta de nuevo en unos minutos
3. Los servidores de DuckDuckGo pueden estar temporalmente no disponibles

### Las contraseñas aparecen cifradas en el CSV

**Causa**: Error al descifrar con la secret key.

**Solución**:
1. Verifica que el Recovery Code sea completo
2. Intenta regenerar el Recovery Code desde la app
3. Ejecuta con `-v` para ver más detalles del error

### No tengo Sync & Backup en mi app

**Causa**: Feature no disponible o desactivada.

**Solución**:
1. Actualiza DuckDuckGo a la última versión
2. Sync & Backup debe activarse manualmente en Settings
3. Necesitas crear o unirte a un grupo de sincronización

---

## 📝 Changelog

### [1.1.0] - 2026-01-18

#### Added
- Soporte para códigos multilínea del PDF
- Formatos de exportación: ProtonPass, NordPass, RoboForm, Keeper
- Mejor manejo de errores con mensajes descriptivos

#### Changed
- El modo interactivo ahora acepta múltiples líneas (ENTER vacío para terminar)
- Mejorada la limpieza del Recovery Code (elimina espacios, saltos de línea, etc.)

#### Fixed
- Error al pegar código del PDF con saltos de línea

### [1.0.0] - 2026-01-18

#### Added
- Exportación inicial a CSV, JSON, Bitwarden, 1Password
- Soporte para Recovery Code de DuckDuckGo
- Implementación de criptografía compatible (PyNaCl)
- CLI interactivo
- Descifrado de todos los campos (domain, username, password, notes)

---

## 👤 Autor

**Homero Thompson del Lago del Terror**

---

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

```
MIT License

Copyright (c) 2026 Homero Thompson del Lago del Terror

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚖️ Disclaimer

Este proyecto **no está afiliado, asociado, autorizado, respaldado por, ni de ninguna manera oficialmente conectado con DuckDuckGo, Inc.**, ni con ninguna de sus subsidiarias o afiliadas.

El nombre "DuckDuckGo" así como nombres, marcas, emblemas e imágenes relacionadas son marcas registradas de sus respectivos propietarios.

**Usa esta herramienta bajo tu propio riesgo.** El autor no se hace responsable por cualquier pérdida de datos, brechas de seguridad, o cualquier otro daño derivado del uso de esta herramienta.

---

<div align="center">

**¿Te fue útil? ⭐ Dale una estrella al repositorio**

</div>