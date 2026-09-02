# HashyMime

> **A modern, all-in-one file forensics, metadata extraction, cryptographic hashing, and threat intelligence desktop tool.**

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![UI Framework](https://img.shields.io/badge/GUI-CustomTkinter-00BFA5.svg)](https://github.com/TomSchimansky/CustomTkinter)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

---

## Table of Contents

- [Why HashyMime? (Motivation)](#why-hashymime-motivation)
- [Key Features](#key-features)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Supported File & Metadata Formats](#supported-file--metadata-formats)
- [UI Overview](#ui-overview)
- [Tech Stack & Libraries](#tech-stack--libraries)
- [Installation & Setup](#installation--setup)
- [Configuration (.env)](#configuration-env)
- [Usage Guide](#usage-guide)
- [Project Architecture](#project-architecture)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)

---

## Why HashyMime? (Motivation)

On operating systems like **Windows**, basic file analysis and cryptographic hash calculations are inconvenient out of the box:

- **No Built-in GUI Hash Calculator**: Windows File Explorer provides no native context menu or property tab to verify MD5, SHA-256, or SHA-3 checksums. Users are forced to open PowerShell (`Get-FileHash`) or Command Prompt (`CertUtil -hashfile ...`), typing repetitive commands that compute only one hash at a time.
- **Fragmented Metadata Inspection**: Native properties only display basic attributes. EXIF photo coordinates, audio bitrates/tags, video frame counts, PDF structure revisions, and Office document histories are scattered across disparate tools.
- **Disconnected Threat Analysis**: Checking whether an unknown or suspicious download contains malware usually requires manually navigating to VirusTotal and uploading the file.

**HashyMime solves all of this in a single, lightweight desktop application.** Simply select any file to generate cryptographic hashes, extract file metadata, and query VirusTotal threat intelligence asynchronously without blocking the UI.

---

## Key Features

- **Multi-Family Cryptographic Hashes**: Calculates MD2, MD4, MD5, SHA-0, SHA-1, SHA-2 (SHA-224/256/384/512), SHA-3 (SHA3-224/256/384/512), and BLAKE2 (BLAKE2b/BLAKE2s).
- **Deep Metadata Extraction**: Universal format inspector covering images (EXIF, HEIC), audio (ID3, Vorbis, bitrate), video (resolution, FPS, duration), documents (PDF, DOCX, PPTX, XLSX), and raw binary streams.
- **Detailed Filesystem & OS Inspection**: Displays file sizes (formatted and raw bytes), MAC timestamps (Created, Modified, Accessed), octal and `rwxrwxrwx` permissions, MIME types, Inode numbers, device IDs, and hard links.
- **VirusTotal v3 Integration**:
  - Performs a SHA-256 hash lookup first to conserve API upload quotas.
  - Automatically uploads unknown files and polls for scan results.
  - Displays verdict status (Clean, Suspicious, Malicious), a per-engine detection table, and a direct link to the web report.
- **Non-Blocking Multithreading**: Computation, file reading, and network calls run on background threads.
- **One-Click Clipboard Copying**: Every hash, metadata key, and file property includes a dedicated copy button.
- **Modern Dark UI**: Built with CustomTkinter featuring slate and teal styling, responsive layout, and breadcrumb navigation.

---

## Supported Hash Algorithms

| Family | Algorithm | Implementation Details |
| :--- | :--- | :--- |
| **MD Family** | **MD2** | Pure Python implementation (RFC 1319 compliant) |
| | **MD4** | Pure Python implementation (RFC 1320 compliant) |
| | **MD5** | Native Python `hashlib` |
| **SHA Family** | **SHA-0** | Pure Python implementation (Original 1993 FIPS 180 standard) |
| | **SHA-1** | Native Python `hashlib` |
| | **SHA-2** | SHA-224, SHA-256, SHA-384, SHA-512 |
| | **SHA-3** | SHA3-224, SHA3-256, SHA3-384, SHA3-512 |
| **BLAKE Family** | **BLAKE2** | BLAKE2b, BLAKE2s |

---

## Supported File & Metadata Formats

| Category | Extensions | Extracted Metadata & Engines |
| :--- | :--- | :--- |
| **Images** | `.jpg`, `.jpeg`, `.png`, `.heic`, `.heif`, `.webp`, `.bmp`, `.tiff` | EXIF tags (camera model, exposure, GPS tags, date), resolution, dimensions, color mode (`Pillow`, `pillow-heif`, `exifread`) |
| **Audio** | `.mp3`, `.flac`, `.ogg`, `.wav`, `.m4a`, etc. | Duration, bitrate, sample rate, artist, album, title, ID3/Vorbis tags (`mutagen`) |
| **Video** | `.mp4`, `.mkv`, `.avi`, `.mov`, `.webm` | Resolution (width x height), frame rate (FPS), total frame count, duration in seconds (`opencv-python` / `cv2`, `mutagen`) |
| **Documents** | `.pdf` | Author, title, subject, creator, producer, page count (`pypdf`) |
| **Word** | `.docx` | Author, revision, last modified by, creation/modified dates, keywords (`python-docx`) |
| **PowerPoint**| `.pptx` | Slide count, author, title, keywords, subject (`python-pptx`) |
| **Excel** | `.xlsx` | Sheet count, sheet names, creator, last modified by (`openpyxl`) |
| **Universal Binary** | Any file format | Binary headers, MIME types, container information (`hachoir`) |

---

## UI Overview

HashyMime features a breadcrumb navigation bar to jump between analysis views:

1. **Hash Tab**: Cryptographic digest calculation table with copy buttons.
2. **Metadata Tab**: Format-specific metadata fields filtered by file type.
3. **File Info Tab**: MAC timestamps, raw/formatted file sizes, drive partitions, and permissions.
4. **VirusTotal Tab**: Antivirus engine analysis breakdown and threat verdict banner.
5. **Upload Tab**: File selector to reload or analyze another file.

---

## Tech Stack & Libraries

HashyMime is built in **Python 3.10+** utilizing the following libraries:

| Library | Version | Purpose |
| :--- | :--- | :--- |
| [`customtkinter`](https://github.com/TomSchimansky/CustomTkinter) | `>= 5.2.0` | Modern dark-mode graphical user interface |
| [`Pillow`](https://python-pillow.org/) | `>= 10.0.0` | Core image processing and basic EXIF reading |
| [`pillow-heif`](https://github.com/bigcat88/pillow_heif) | `>= 0.14.0` | Support for Apple HEIC/HEIF image formats |
| [`mutagen`](https://mutagen.readthedocs.io/) | `>= 1.47.0` | Audio stream analysis and ID3 / metadata tag parsing |
| [`opencv-python`](https://github.com/opencv/opencv-python) | `>= 4.8.0` | Video frame decoding, FPS, and resolution detection |
| [`pypdf`](https://pypdf.readthedocs.io/) | `>= 4.0.0` | PDF metadata, structure, and page count extraction |
| [`python-docx`](https://python-docx.readthedocs.io/) | `>= 1.1.0` | Microsoft Word (`.docx`) metadata inspection |
| [`python-pptx`](https://python-pptx.readthedocs.io/) | `>= 0.6.23` | Microsoft PowerPoint (`.pptx`) metadata inspection |
| [`openpyxl`](https://openpyxl.readthedocs.io/) | `>= 3.1.2` | Microsoft Excel (`.xlsx`) metadata inspection |
| [`exifread`](https://github.com/ianare/exif-py) | `>= 3.0.0` | Detailed EXIF camera metadata parsing |
| [`hachoir`](https://hachoir.readthedocs.io/) | `>= 3.2.0` | Stream parsing and generic binary container inspection |
| [`vt-py`](https://github.com/VirusTotal/vt-py) | `>= 0.18.0` | Official VirusTotal v3 REST API client |
| [`python-dotenv`](https://github.com/theskumar/python-dotenv) | `>= 1.0.0` | Environment variable management for `.env` credentials |

---

## Installation & Setup

### Prerequisites

- **Python 3.10 or higher** installed on your system. ([Download Python](https://www.python.org/downloads/))
- **Git** (optional, for cloning).

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/HashyMime.git
cd HashyMime
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration (.env)

HashyMime works offline for hashes, metadata, and file information. To enable the **VirusTotal Scan** feature, configure an API key:

1. Create a free account on [VirusTotal](https://www.virustotal.com/).
2. Copy your API key from the profile dashboard.
3. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
4. Open `.env` in a text editor and enter your API key:
   ```env
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

---

## Usage Guide

1. **Launch the Application**:
   ```bash
   python main.py
   ```
2. **Open a File**:
   - Click the **"Datei oeffnen"** button on the start screen.
   - Select any file from your file explorer.
3. **Explore the Results**:
   - **Hash**: View all hashes simultaneously and click **Copy** next to any row.
   - **Metadaten**: View EXIF, audio, video, or document attributes.
   - **Datei-Infos**: Check timestamps, raw byte sizes, and permissions.
   - **VirusTotal**: View AV engine detection results and open the online report.
   - **Upload**: Load another file at any time.

---

## Project Architecture

```
HashyMime/
├── .env.example              # Template for environment variables (API keys)
├── .gitignore                # Git ignore rules
├── requirements.txt          # Python dependencies
├── main.py                   # Main GUI application & CustomTkinter layout
└── modules/
    ├── __init__.py           # Package initializer
    ├── hashes.py             # Pure-Python MD2, MD4, SHA-0 & hashlib hash engines
    ├── fileinfo.py           # OS stats, MAC timestamps, permissions & sizes
    ├── metadata.py           # Multi-format metadata extractor (EXIF, Audio, Video, Docs)
    └── virustotal.py         # VirusTotal v3 API hash lookup & upload handler
```

---

## Troubleshooting & FAQ

<details>
<summary><b>Why do MD2, MD4, and SHA-0 not require external C extensions?</b></summary>
<p>
Modern versions of OpenSSL and Python have deprecated or removed older legacy algorithms like MD2 and SHA-0. HashyMime includes standalone, pure-Python reference implementations of MD2, MD4, and SHA-0 for full cross-platform compatibility.
</p>
</details>

<details>
<summary><b>Does HashyMime upload all files to VirusTotal?</b></summary>
<p>
No. HashyMime first queries VirusTotal's database using the local SHA-256 hash. Only unknown files are uploaded for a scan.
</p>
</details>

<details>
<summary><b>Can HashyMime run on Linux or macOS?</b></summary>
<p>
Yes. CustomTkinter and all underlying libraries are cross-platform. On Linux, ensure Tkinter is installed (e.g., <code>sudo apt install python3-tk</code>).
</p>
</details>

---

## License

This project is licensed under the [MIT License](LICENSE).

