"""Mehrsprachigkeits-Modul (i18n) fuer HashyMime.
Unterstuetzt Deutsch, Englisch, Franzoesisch und Spanisch (ohne Emojis).
"""

LANGUAGES = {
    "Deutsch": "de",
    "English": "en",
    "Français": "fr",
    "Español": "es",
}

LANG_NAMES = {v: k for k, v in LANGUAGES.items()}

_CURRENT_LANG = "de"

TRANSLATIONS = {
    "de": {
        # App & Header
        "app_title": "HashyMime",
        "app_subtitle": "Datei-Forensik und Metadaten-Analyse",
        "no_file": "Keine Datei geladen",
        "file_prefix": "Datei: ",
        "new_tab": "Neuer Tab",
        "close_tab": "Tab schließen",
        "tab_file": "Datei",
        "lang_label": "Sprache:",
        
        # Navigation / Breadcrumbs
        "nav_hash": "Hash",
        "nav_metadata": "Metadaten",
        "nav_fileinfo": "Datei-Infos",
        "nav_virustotal": "VirusTotal",
        "nav_upload": "Laden",
        "nav_compare": "Vergleich",

        # Upload / Start
        "upload_title": "Neue Datei laden",
        "upload_subtitle": "Wähle eine andere Datei zur Analyse.",
        "drop_title": "Datei auswählen",
        "drop_hint": "Hier klicken oder Datei auswählen",
        "btn_open": "Datei öffnen",
        "btn_add_file": "+ Neuer Tab",
        "open_dialog_title": "Datei zur Analyse auswählen",

        # Hashes Tab (On-Demand)
        "hashes_header": "Kryptographische Hashes",
        "hashes_calc_prompt": "Hashes noch nicht berechnet",
        "hashes_calc_desc": "Klicke auf 'Errechnen', um kryptographische Prüfsummen (MD5, SHA-1, SHA-256, SHA-512 etc.) zu berechnen.",
        "hashes_computing": "Berechne Hashes...",
        "hashes_copy": "Kopieren",
        "hashes_copied": "Kopiert!",
        "btn_calculate": "Errechnen",
        "btn_recalculate": "Neu errechnen",

        # Metadata Tab (Sofort)
        "meta_header": "Metadaten",
        "meta_reading": "Lese Metadaten...",
        "meta_found": "{count} Metadaten gefunden",
        "meta_none": "Keine Metadaten gefunden",

        # File Info Tab
        "info_header": "Datei-Informationen",
        "info_filename": "Dateiname",
        "info_extension": "Erweiterung",
        "info_mimetype": "MIME-Typ",
        "info_abspath": "Absoluter Pfad",
        "info_dir": "Verzeichnis",
        "info_drive": "Laufwerk",
        "info_size": "Dateigröße",
        "info_size_raw": "Dateigröße (raw Bytes)",
        "info_ctime": "Erstellungsdatum (ctime)",
        "info_mtime": "Änderungsdatum (mtime)",
        "info_atime": "Letzter Zugriff (atime)",
        "info_perms_octal": "Zugriffsrechte (octal)",
        "info_perms_rwx": "Zugriffsrechte (rwx)",
        "info_readable": "Lesbar",
        "info_writable": "Schreibbar",
        "info_executable": "Ausführbar",
        "info_owner_uid": "Owner UID",
        "info_group_gid": "Gruppen GID",
        "info_inode": "Inode",
        "info_hardlinks": "Hardlinks",
        "info_device": "Gerät (Device ID)",
        "yes": "Ja",
        "no": "Nein",

        # VirusTotal Tab
        "vt_header": "VirusTotal Scan",
        "vt_connecting": "Verbinde mit VirusTotal...",
        "vt_error": "Fehler: {error}",
        "vt_clean": "SAUBER",
        "vt_suspicious": "VERDAECHTIG",
        "vt_danger": "GEFAEHRRLICH",
        "vt_detected": "Detektiert: {detected}/{total}",
        "vt_malicious": "Malicious: {malicious}",
        "vt_suspicious_count": "Suspicious: {suspicious}",
        "vt_undetected": "Undetected: {undetected}",
        "vt_open_report": "VirusTotal Bericht öffnen",
        "vt_scanner_results": "Scanner-Ergebnisse ({count})",

        # Compare Tab
        "compare_header": "Datei-Vergleich (Diff)",
        "compare_select_hint": "Wähle zwei geöffnete Dateien aus, um sie direkt zu vergleichen:",
        "compare_file_a": "Datei 1",
        "compare_file_b": "Datei 2",
        "compare_btn": "Dateien vergleichen",
        "compare_match": "Gleich",
        "compare_diff": "Abweichend",
        "compare_identical": "Beide Dateien sind identisch (gleicher SHA-256 Hash)!",
        "compare_different": "Die Dateien unterscheiden sich im Inhalt.",
        "compare_need_two": "Bitte öffne mindestens 2 Dateien in Tabs, um sie vergleichen zu können.",
        "property": "Eigenschaft",
        "status": "Status",
    },
    "en": {
        # App & Header
        "app_title": "HashyMime",
        "app_subtitle": "File Forensics and Metadata Analysis",
        "no_file": "No file loaded",
        "file_prefix": "File: ",
        "new_tab": "New Tab",
        "close_tab": "Close Tab",
        "tab_file": "File",
        "lang_label": "Language:",

        # Navigation / Breadcrumbs
        "nav_hash": "Hashes",
        "nav_metadata": "Metadata",
        "nav_fileinfo": "File Info",
        "nav_virustotal": "VirusTotal",
        "nav_upload": "Open",
        "nav_compare": "Compare",

        # Upload / Start
        "upload_title": "Open New File",
        "upload_subtitle": "Choose another file to analyze.",
        "drop_title": "Select File",
        "drop_hint": "Click here or choose a file",
        "btn_open": "Open File",
        "btn_add_file": "+ New Tab",
        "open_dialog_title": "Select file for analysis",

        # Hashes Tab (On-Demand)
        "hashes_header": "Cryptographic Hashes",
        "hashes_calc_prompt": "Hashes not calculated yet",
        "hashes_calc_desc": "Click 'Calculate' to compute cryptographic checksums (MD5, SHA-1, SHA-256, SHA-512, etc.).",
        "hashes_computing": "Computing hashes...",
        "hashes_copy": "Copy",
        "hashes_copied": "Copied!",
        "btn_calculate": "Calculate",
        "btn_recalculate": "Recalculate",

        # Metadata Tab (Immediate)
        "meta_header": "Metadata",
        "meta_reading": "Reading metadata...",
        "meta_found": "{count} metadata entries found",
        "meta_none": "No metadata found",

        # File Info Tab
        "info_header": "File Information",
        "info_filename": "File Name",
        "info_extension": "Extension",
        "info_mimetype": "MIME Type",
        "info_abspath": "Absolute Path",
        "info_dir": "Directory",
        "info_drive": "Drive",
        "info_size": "File Size",
        "info_size_raw": "File Size (raw Bytes)",
        "info_ctime": "Created Date (ctime)",
        "info_mtime": "Modified Date (mtime)",
        "info_atime": "Last Accessed (atime)",
        "info_perms_octal": "Permissions (octal)",
        "info_perms_rwx": "Permissions (rwx)",
        "info_readable": "Readable",
        "info_writable": "Writable",
        "info_executable": "Executable",
        "info_owner_uid": "Owner UID",
        "info_group_gid": "Group GID",
        "info_inode": "Inode",
        "info_hardlinks": "Hardlinks",
        "info_device": "Device ID",
        "yes": "Yes",
        "no": "No",

        # VirusTotal Tab
        "vt_header": "VirusTotal Scan",
        "vt_connecting": "Connecting to VirusTotal...",
        "vt_error": "Error: {error}",
        "vt_clean": "CLEAN",
        "vt_suspicious": "SUSPICIOUS",
        "vt_danger": "MALICIOUS",
        "vt_detected": "Detected: {detected}/{total}",
        "vt_malicious": "Malicious: {malicious}",
        "vt_suspicious_count": "Suspicious: {suspicious}",
        "vt_undetected": "Undetected: {undetected}",
        "vt_open_report": "Open VirusTotal Report",
        "vt_scanner_results": "Scanner Results ({count})",

        # Compare Tab
        "compare_header": "File Comparison (Diff)",
        "compare_select_hint": "Select two open files to compare side-by-side:",
        "compare_file_a": "File 1",
        "compare_file_b": "File 2",
        "compare_btn": "Compare Files",
        "compare_match": "Match",
        "compare_diff": "Different",
        "compare_identical": "Both files are identical (matching SHA-256 hash)!",
        "compare_different": "The file contents differ.",
        "compare_need_two": "Please open at least 2 files in tabs to compare them.",
        "property": "Property",
        "status": "Status",
    },
    "fr": {
        # App & Header
        "app_title": "HashyMime",
        "app_subtitle": "Expertise forensique et analyse de métadonnées",
        "no_file": "Aucun fichier chargé",
        "file_prefix": "Fichier : ",
        "new_tab": "Nouvel onglet",
        "close_tab": "Fermer l'onglet",
        "tab_file": "Fichier",
        "lang_label": "Langue :",

        # Navigation / Breadcrumbs
        "nav_hash": "Hachages",
        "nav_metadata": "Métadonnées",
        "nav_fileinfo": "Infos fichier",
        "nav_virustotal": "VirusTotal",
        "nav_upload": "Ouvrir",
        "nav_compare": "Comparer",

        # Upload / Start
        "upload_title": "Ouvrir un nouveau fichier",
        "upload_subtitle": "Choisissez un autre fichier à analyser.",
        "drop_title": "Sélectionner un fichier",
        "drop_hint": "Cliquez ici ou choisissez un fichier",
        "btn_open": "Ouvrir le fichier",
        "btn_add_file": "+ Nouvel onglet",
        "open_dialog_title": "Sélectionner un fichier pour analyse",

        # Hashes Tab (On-Demand)
        "hashes_header": "Hachages Cryptographiques",
        "hashes_calc_prompt": "Hachages non calculés",
        "hashes_calc_desc": "Cliquez sur 'Calculer' pour calculer les sommes de contrôle cryptographiques (MD5, SHA-1, SHA-256, etc.).",
        "hashes_computing": "Calcul des hachages...",
        "hashes_copy": "Copier",
        "hashes_copied": "Copié !",
        "btn_calculate": "Calculer",
        "btn_recalculate": "Recalculer",

        # Metadata Tab (Immediate)
        "meta_header": "Métadonnées",
        "meta_reading": "Lecture des métadonnées...",
        "meta_found": "{count} métadonnées trouvées",
        "meta_none": "Aucune métadonnée trouvée",

        # File Info Tab
        "info_header": "Informations sur le fichier",
        "info_filename": "Nom du fichier",
        "info_extension": "Extension",
        "info_mimetype": "Type MIME",
        "info_abspath": "Chemin absolu",
        "info_dir": "Répertoire",
        "info_drive": "Lecteur",
        "info_size": "Taille du fichier",
        "info_size_raw": "Taille (octets bruts)",
        "info_ctime": "Date de création (ctime)",
        "info_mtime": "Date de modification (mtime)",
        "info_atime": "Dernier accès (atime)",
        "info_perms_octal": "Permissions (octal)",
        "info_perms_rwx": "Permissions (rwx)",
        "info_readable": "Lisible",
        "info_writable": "Modifiable",
        "info_executable": "Exécutable",
        "info_owner_uid": "UID Propriétaire",
        "info_group_gid": "GID Groupe",
        "info_inode": "Inode",
        "info_hardlinks": "Liens physiques",
        "info_device": "ID Périphérique",
        "yes": "Oui",
        "no": "Non",

        # VirusTotal Tab
        "vt_header": "Analyse VirusTotal",
        "vt_connecting": "Connexion à VirusTotal...",
        "vt_error": "Erreur : {error}",
        "vt_clean": "PROPRE",
        "vt_suspicious": "SUSPECT",
        "vt_danger": "DANGEREUX",
        "vt_detected": "Détecté : {detected}/{total}",
        "vt_malicious": "Malveillant : {malicious}",
        "vt_suspicious_count": "Suspect : {suspicious}",
        "vt_undetected": "Non détecté : {undetected}",
        "vt_open_report": "Ouvrir le rapport VirusTotal",
        "vt_scanner_results": "Résultats des scanners ({count})",

        # Compare Tab
        "compare_header": "Comparaison de fichiers (Diff)",
        "compare_select_hint": "Sélectionnez deux fichiers ouverts à comparer :",
        "compare_file_a": "Fichier 1",
        "compare_file_b": "Fichier 2",
        "compare_btn": "Comparer les fichiers",
        "compare_match": "Identique",
        "compare_diff": "Différent",
        "compare_identical": "Les deux fichiers sont identiques (même hachage SHA-256) !",
        "compare_different": "Le contenu des fichiers est différent.",
        "compare_need_two": "Veuillez ouvrir au moins 2 fichiers dans des onglets pour les comparer.",
        "property": "Propriété",
        "status": "Statut",
    },
    "es": {
        # App & Header
        "app_title": "HashyMime",
        "app_subtitle": "Forense de archivos y análisis de metadatos",
        "no_file": "Ningún archivo cargado",
        "file_prefix": "Archivo: ",
        "new_tab": "Nueva pestaña",
        "close_tab": "Cerrar pestaña",
        "tab_file": "Archivo",
        "lang_label": "Idioma:",

        # Navigation / Breadcrumbs
        "nav_hash": "Hashes",
        "nav_metadata": "Metadatos",
        "nav_fileinfo": "Info de archivo",
        "nav_virustotal": "VirusTotal",
        "nav_upload": "Abrir",
        "nav_compare": "Comparar",

        # Upload / Start
        "upload_title": "Cargar nuevo archivo",
        "upload_subtitle": "Elija otro archivo para analizar.",
        "drop_title": "Seleccionar archivo",
        "drop_hint": "Haga clic aquí o elija un archivo",
        "btn_open": "Abrir archivo",
        "btn_add_file": "+ Nueva pestaña",
        "open_dialog_title": "Seleccionar archivo para análisis",

        # Hashes Tab (On-Demand)
        "hashes_header": "Hashes Criptográficos",
        "hashes_calc_prompt": "Hashes no calculados todavía",
        "hashes_calc_desc": "Haga clic en 'Calcular' para calcular las sumas de comprobación criptográficas (MD5, SHA-1, SHA-256, etc.).",
        "hashes_computing": "Calculando hashes...",
        "hashes_copy": "Copiar",
        "hashes_copied": "¡Copiado!",
        "btn_calculate": "Calcular",
        "btn_recalculate": "Recalcular",

        # Metadata Tab (Immediate)
        "meta_header": "Metadatos",
        "meta_reading": "Leyendo metadatos...",
        "meta_found": "{count} metadatos encontrados",
        "meta_none": "No se encontraron metadatos",

        # File Info Tab
        "info_header": "Información del archivo",
        "info_filename": "Nombre del archivo",
        "info_extension": "Extensión",
        "info_mimetype": "Tipo MIME",
        "info_abspath": "Ruta absoluta",
        "info_dir": "Directorio",
        "info_drive": "Unidad",
        "info_size": "Tamaño del archivo",
        "info_size_raw": "Tamaño (Bytes brutos)",
        "info_ctime": "Fecha de creación (ctime)",
        "info_mtime": "Fecha de modificación (mtime)",
        "info_atime": "Último acceso (atime)",
        "info_perms_octal": "Permisos (octal)",
        "info_perms_rwx": "Permisos (rwx)",
        "info_readable": "Legible",
        "info_writable": "Modificable",
        "info_executable": "Ejecutable",
        "info_owner_uid": "UID Propietario",
        "info_group_gid": "GID Grupo",
        "info_inode": "Inodo",
        "info_hardlinks": "Enlaces duros",
        "info_device": "ID de Dispositivo",
        "yes": "Sí",
        "no": "No",

        # VirusTotal Tab
        "vt_header": "Análisis de VirusTotal",
        "vt_connecting": "Conectando a VirusTotal...",
        "vt_error": "Error: {error}",
        "vt_clean": "LIMPIO",
        "vt_suspicious": "SOSPECHOSO",
        "vt_danger": "PELIGROSO",
        "vt_detected": "Detectado: {detected}/{total}",
        "vt_malicious": "Malicioso: {malicious}",
        "vt_suspicious_count": "Sospechoso: {suspicious}",
        "vt_undetected": "No detectado: {undetected}",
        "vt_open_report": "Abrir reporte de VirusTotal",
        "vt_scanner_results": "Resultados de escáner ({count})",

        # Compare Tab
        "compare_header": "Comparación de archivos (Diff)",
        "compare_select_hint": "Seleccione dos archivos abiertos para comparar lado a lado:",
        "compare_file_a": "Archivo 1",
        "compare_file_b": "Archivo 2",
        "compare_btn": "Comparar archivos",
        "compare_match": "Coincide",
        "compare_diff": "Diferente",
        "compare_identical": "¡Ambos archivos son idénticos (mismo hash SHA-256)!",
        "compare_different": "El contenido de los archivos difiere.",
        "compare_need_two": "Abra al menos 2 archivos en pestañas para poder compararlos.",
        "property": "Propiedad",
        "status": "Estado",
    }
}


def set_language(lang: str):
    global _CURRENT_LANG
    if lang in TRANSLATIONS:
        _CURRENT_LANG = lang
    elif lang in LANGUAGES:
        _CURRENT_LANG = LANGUAGES[lang]


def get_language() -> str:
    return _CURRENT_LANG


def t(key: str, **kwargs) -> str:
    text = TRANSLATIONS.get(_CURRENT_LANG, TRANSLATIONS["de"]).get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text
