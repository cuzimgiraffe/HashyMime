"""VirusTotal API-Client fuer Hash-Lookups und Datei-Scans."""

import hashlib
import time
import os


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def scan_file(path: str, api_key: str, progress_callback=None) -> dict:
    try:
        import vt
    except ImportError:
        return {"error": "vt-py nicht installiert"}

    result = {
        "sha256": "",
        "name": os.path.basename(path),
        "status": "",
        "stats": {},
        "engines": [],
        "permalink": "",
    }

    sha256 = _sha256(path)
    result["sha256"] = sha256

    client = vt.Client(api_key)
    try:
        # SHA256-Abfrage zur Vermeidung unnoetiger Uploads.
        if progress_callback:
            progress_callback("SHA256-Lookup bei VirusTotal...")
        try:
            file_obj = client.get_object(f"/files/{sha256}")
        except vt.error.APIError:
            # Unbekannte Datei zur Analyse hochladen.
            if progress_callback:
                progress_callback("Datei wird hochgeladen...")
            with open(path, "rb") as f:
                analysis = client.scan_file(f)

            # Auf Abschluss der Analyse warten.
            analysis_id = analysis.id
            for _ in range(60):
                if progress_callback:
                    progress_callback("Warte auf Scan-Ergebnis...")
                time.sleep(5)
                analysis_obj = client.get_object(f"/analyses/{analysis_id}")
                if analysis_obj.status == "completed":
                    break

            # Datei-Objekt nach Abschluss abrufen.
            file_obj = client.get_object(f"/files/{sha256}")

        # Scan-Ergebnisse strukturieren.
        result["status"] = "completed"
        result["permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"

        attrs = file_obj
        stats = getattr(attrs, "last_analysis_stats", {})
        result["stats"] = dict(stats) if stats else {}

        engines_raw = getattr(attrs, "last_analysis_results", {})
        for engine, data in (engines_raw.items() if engines_raw else []):
            result["engines"].append({
                "engine": engine,
                "category": data.get("category", ""),
                "result": data.get("result", "") or "-",
            })

        # Erkannte Bedrohungen zuerst anzeigen.
        result["engines"].sort(key=lambda x: x["category"] not in ("malicious", "suspicious"))

    except Exception as e:
        result["error"] = str(e)
    finally:
        client.close()

    return result
