"""Datei-Informationen wie Name, Groesse, Zeitstempel, Pfad und Rechte."""

import os
import stat
import mimetypes
import datetime


def _format_time(ts) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} Bytes"
    elif size < 1024 ** 2:
        return f"{size / 1024:.2f} KB  ({size} Bytes)"
    elif size < 1024 ** 3:
        return f"{size / 1024**2:.2f} MB  ({size} Bytes)"
    else:
        return f"{size / 1024**3:.2f} GB  ({size} Bytes)"


def _parse_permissions(mode: int) -> str:
    # Berechtigungs-String im Standardformat zusammenbauen.
    perms = ""
    for who in [(stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR),
                (stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP),
                (stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH)]:
        perms += "r" if mode & who[0] else "-"
        perms += "w" if mode & who[1] else "-"
        perms += "x" if mode & who[2] else "-"
        perms += " "
    return perms.strip()


def get_all(path: str) -> dict:
    info = {}
    st = os.stat(path)

    # Basisinformationen
    info["Dateiname"] = os.path.basename(path)
    info["Erweiterung"] = os.path.splitext(path)[1] or "(keine)"
    mime, _ = mimetypes.guess_type(path)
    info["MIME-Typ"] = mime or "unbekannt"
    info["Absoluter Pfad"] = os.path.abspath(path)
    info["Verzeichnis"] = os.path.dirname(os.path.abspath(path))

    # Laufwerk ermitteln
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    info["Laufwerk"] = drive if drive else "/"

    # Dateigroesse
    info["Dateigröße"] = _format_size(st.st_size)
    info["Dateigröße (raw Bytes)"] = str(st.st_size)

    # Zeitstempel
    info["Erstellungsdatum (ctime)"] = _format_time(st.st_ctime)
    info["Änderungsdatum (mtime)"] = _format_time(st.st_mtime)
    info["Letzter Zugriff (atime)"] = _format_time(st.st_atime)

    # Zugriffsrechte
    info["Zugriffsrechte (octal)"] = oct(stat.S_IMODE(st.st_mode))
    info["Zugriffsrechte (rwx)"] = _parse_permissions(st.st_mode)
    info["Lesbar"] = "Ja" if os.access(path, os.R_OK) else "Nein"
    info["Schreibbar"] = "Ja" if os.access(path, os.W_OK) else "Nein"
    info["Ausführbar"] = "Ja" if os.access(path, os.X_OK) else "Nein"

    # Dateisystem-IDs
    info["Owner UID"] = str(st.st_uid)
    info["Gruppen GID"] = str(st.st_gid)
    info["Inode"] = str(st.st_ino)
    info["Hardlinks"] = str(st.st_nlink)
    info["Gerät (Device ID)"] = str(st.st_dev)

    return info
