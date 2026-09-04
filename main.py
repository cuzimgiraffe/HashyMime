"""HashyMime - Desktop-Anwendung zur Datei-Analyse, Forensik und Metadaten-Inspektion."""

import os
import threading
from tkinter import filedialog
import customtkinter as ctk
from dotenv import load_dotenv

from modules import hashes, metadata, fileinfo, virustotal, i18n
from modules.i18n import t

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Farb- und Layoutkonfiguration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT     = "#00BFA5"
ACCENT_DIM = "#007A6B"
BG_CARD    = "#1E1E2E"
BG_MAIN    = "#12121C"
BG_ROW_A   = "#1A1A2A"
BG_ROW_B   = "#1E1E30"
BG_TAB_ACT = "#252538"
BG_TAB_IN  = "#171724"
TXT        = "#E0E0F0"
TXT_DIM    = "#8888AA"
DANGER     = "#FF4F4F"
WARN       = "#FFB347"
OK         = "#4CAF50"

FONT_HEAD  = ("Segoe UI", 22, "bold")
FONT_SUB   = ("Segoe UI", 13)
FONT_MONO  = ("Consolas", 11)
FONT_LABEL = ("Segoe UI", 11)
FONT_CRUMB = ("Segoe UI", 12, "bold")
FONT_TAB   = ("Segoe UI", 11, "bold")


def copy_to_clipboard(root: ctk.CTk, text: str):
    """Kopiert Text in die Zwischenablage."""
    root.clipboard_clear()
    root.clipboard_append(text)


def make_card(parent, **kwargs) -> ctk.CTkFrame:
    """Erstellt einen einheitlichen Karten-Container."""
    return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12, **kwargs)


def make_label(parent, text, font=None, color=TXT, **kwargs) -> ctk.CTkLabel:
    """Erstellt ein einheitlich formatiertes Textlabel."""
    return ctk.CTkLabel(parent, text=text, font=font or FONT_LABEL,
                        text_color=color, **kwargs)


class DataTable(ctk.CTkScrollableFrame):
    """Scrollbare Key-Value Tabelle mit integriertem Kopier-Button."""

    def __init__(self, parent, rows: list[tuple], copyable=True, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._copyable = copyable
        self._build(rows, copyable)

    def _copy(self, btn: ctk.CTkButton, text: str):
        self.winfo_toplevel().clipboard_clear()
        self.winfo_toplevel().clipboard_append(text)
        orig_text = btn.cget("text")
        btn.configure(text=t("hashes_copied"), fg_color=ACCENT_DIM)
        self.after(1200, lambda: btn.configure(text=t("hashes_copy"), fg_color=BG_ROW_B))

    def _build(self, rows, copyable):
        if hasattr(self, "_row_widgets"):
            for w in self._row_widgets:
                w.destroy()
        self._row_widgets = []

        self.grid_columnconfigure(1, weight=1)

        for i, (key, val) in enumerate(rows):
            bg = BG_ROW_A if i % 2 == 0 else BG_ROW_B
            
            lbl_key = ctk.CTkLabel(
                self, text=key, font=("Segoe UI", 11, "bold"),
                text_color=ACCENT, anchor="w", width=220, fg_color=bg, corner_radius=6
            )
            lbl_key.grid(row=i, column=0, padx=(10, 6), pady=2, sticky="nsew")
            
            lbl_val = ctk.CTkLabel(
                self, text=str(val), font=FONT_MONO,
                text_color=TXT, anchor="w", wraplength=520, fg_color=bg, corner_radius=6
            )
            lbl_val.grid(row=i, column=1, padx=4, pady=2, sticky="nsew")
            
            self._row_widgets.extend([lbl_key, lbl_val])

            if copyable:
                btn = ctk.CTkButton(
                    self, text=t("hashes_copy"), width=60, height=24,
                    fg_color=BG_ROW_B, hover_color=ACCENT_DIM, font=("Segoe UI", 10),
                    command=lambda b=None, v=str(val): None
                )
                btn.configure(command=lambda b=btn, v=str(val): self._copy(b, v))
                btn.grid(row=i, column=2, padx=(6, 10), pady=2)
                self._row_widgets.append(btn)

    def update_rows(self, rows, copyable=True):
        self._copyable = copyable
        self._build(rows, copyable)


class BrowserTabBar(ctk.CTkScrollableFrame):
    """Horizontale Leiste fuer Tabs im Browser-Design mit 'x'-Schließen-Button."""

    def __init__(self, parent, on_tab_switch, on_tab_close, on_new_tab, **kwargs):
        super().__init__(
            parent, fg_color=BG_CARD, height=44,
            orientation="horizontal", corner_radius=0, **kwargs
        )
        self._on_tab_switch = on_tab_switch
        self._on_tab_close = on_tab_close
        self._on_new_tab = on_new_tab
        self._tabs_data = []
        self._active_tab_id = None
        self._tab_widgets = {}
        self._add_btn = None
        self._build_add_btn()

    def _build_add_btn(self):
        self._add_btn = ctk.CTkButton(
            self, text="+", width=34, height=30,
            fg_color="transparent", hover_color=BG_ROW_B,
            text_color=ACCENT, font=("Segoe UI", 16, "bold"),
            corner_radius=8, command=self._on_new_tab
        )

    def set_tabs(self, tabs_data: list[tuple], active_id):
        self._tabs_data = tabs_data
        self._active_tab_id = active_id
        self._render()

    def _render(self):
        for w in self.winfo_children():
            w.pack_forget()

        for tab_id, title, filepath in self._tabs_data:
            is_active = (tab_id == self._active_tab_id)
            bg = BG_TAB_ACT if is_active else BG_TAB_IN
            border_c = ACCENT if is_active else "#2A2A3E"

            tab_frame = ctk.CTkFrame(
                self, fg_color=bg, corner_radius=8,
                border_width=1, border_color=border_c, height=32
            )
            tab_frame.pack(side="left", padx=3, pady=4)

            display_title = title if len(title) <= 22 else title[:20] + "..."
            lbl = ctk.CTkLabel(
                tab_frame, text=display_title,
                font=FONT_TAB, text_color=TXT if is_active else TXT_DIM,
                cursor="hand2"
            )
            lbl.pack(side="left", padx=(10, 6), pady=4)
            lbl.bind("<Button-1>", lambda e, tid=tab_id: self._on_tab_switch(tid))
            tab_frame.bind("<Button-1>", lambda e, tid=tab_id: self._on_tab_switch(tid))

            close_btn = ctk.CTkButton(
                tab_frame, text="x", width=20, height=20,
                fg_color="transparent", hover_color=DANGER,
                text_color=TXT_DIM, font=("Segoe UI", 11, "bold"),
                corner_radius=10,
                command=lambda tid=tab_id: self._on_tab_close(tid)
            )
            close_btn.pack(side="left", padx=(2, 6), pady=4)

        if self._add_btn:
            self._add_btn.pack(side="left", padx=6, pady=4)


class Breadcrumbs(ctk.CTkFrame):
    """Navigationsleiste fuer die Unteransichten einer Datei."""

    def __init__(self, parent, on_select, **kwargs):
        super().__init__(parent, fg_color=BG_CARD, corner_radius=10, **kwargs)
        self._on_select = on_select
        self._active = 0
        self._btns = []
        self._separators = []
        self._show_compare = False
        self._build()

    def _get_crumb_keys(self):
        keys = ["nav_hash", "nav_metadata", "nav_fileinfo", "nav_virustotal"]
        if self._show_compare:
            keys.append("nav_compare")
        return keys

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        self._btns = []
        self._separators = []

        crumb_keys = self._get_crumb_keys()
        for i, key in enumerate(crumb_keys):
            if i > 0:
                sep = ctk.CTkLabel(self, text=">", font=("Segoe UI", 14), text_color=TXT_DIM)
                sep.pack(side="left", padx=2)
                self._separators.append(sep)

            btn = ctk.CTkButton(
                self, text=t(key), font=FONT_CRUMB,
                fg_color="transparent", hover_color=ACCENT_DIM,
                text_color=TXT_DIM, corner_radius=8,
                width=110, height=36,
                command=lambda idx=i: self.select(idx)
            )
            btn.pack(side="left", padx=2, pady=6)
            self._btns.append(btn)

        self._highlight(self._active)

    def set_show_compare(self, show: bool):
        if self._show_compare != show:
            self._show_compare = show
            self._build()

    def _highlight(self, idx: int):
        for i, btn in enumerate(self._btns):
            if i == idx:
                btn.configure(fg_color=ACCENT, text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=TXT_DIM)

    def select(self, idx: int):
        if idx < len(self._btns):
            self._active = idx
            self._highlight(idx)
            self._on_select(idx)

    def update_texts(self):
        crumb_keys = self._get_crumb_keys()
        for i, btn in enumerate(self._btns):
            if i < len(crumb_keys):
                btn.configure(text=t(crumb_keys[i]))

    def set_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for btn in self._btns:
            btn.configure(state=state)


class HashTab(ctk.CTkFrame):
    """Ansicht fuer kryptographische Hash-Werte mit 'Errechnen'-Button (On-Demand)."""

    def __init__(self, parent, on_calculated=None, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._file_path = None
        self._rows = None
        self._on_calculated = on_calculated

        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        self.title_lbl = make_label(self.header, t("hashes_header"), font=FONT_HEAD, color=ACCENT)
        self.title_lbl.pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, f"{t('file_prefix')}-", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        # Initialer Platzhalter mit "Errechnen"-Button
        self.calc_frame = make_card(self)
        self.prompt_lbl = make_label(self.calc_frame, t("hashes_calc_prompt"), font=("Segoe UI", 16, "bold"), color=TXT)
        self.prompt_lbl.pack(pady=(24, 6))
        self.desc_lbl = make_label(self.calc_frame, t("hashes_calc_desc"), font=("Segoe UI", 12), color=TXT_DIM)
        self.desc_lbl.pack(pady=(0, 18), padx=20)
        
        self.btn_calc = ctk.CTkButton(
            self.calc_frame, text=t("btn_calculate"),
            font=("Segoe UI", 14, "bold"), fg_color=ACCENT, hover_color=ACCENT_DIM,
            height=42, width=200, corner_radius=8, command=self._compute_hashes
        )
        self.btn_calc.pack(pady=(0, 24))

        # Status & Ergebnisse
        self.spinner = make_label(self, t("hashes_computing"), color=TXT_DIM)
        self.top_bar = ctk.CTkFrame(self, fg_color="transparent")
        
        self.btn_recalc = ctk.CTkButton(
            self.top_bar, text=t("btn_recalculate"), width=120, height=28,
            fg_color=BG_ROW_B, hover_color=ACCENT_DIM, font=("Segoe UI", 11),
            command=self._compute_hashes
        )
        self.btn_recalc.pack(side="right", padx=20)

        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str, cached_rows=None):
        self._file_path = file_path
        name = os.path.basename(file_path)
        self.lbl_file.configure(text=f"{t('file_prefix')}{name}")

        self.table.pack_forget()
        self.top_bar.pack_forget()
        self.spinner.pack_forget()
        self.calc_frame.pack_forget()

        if cached_rows is not None:
            self._rows = cached_rows
            self._show(cached_rows)
        else:
            self._rows = None
            self.calc_frame.pack(fill="x", padx=16, pady=24)

    def _compute_hashes(self):
        if not self._file_path:
            return
        self.calc_frame.pack_forget()
        self.table.pack_forget()
        self.top_bar.pack_forget()
        self.spinner.configure(text=t("hashes_computing"))
        self.spinner.pack(pady=20)

        def _compute():
            result = hashes.compute_all(self._file_path)
            rows = list(result.items())
            self._rows = rows
            if self._on_calculated:
                self._on_calculated(self._file_path, rows)
            self.after(0, lambda: self._show(rows))

        threading.Thread(target=_compute, daemon=True).start()

    def _show(self, rows):
        self.spinner.pack_forget()
        self.top_bar.pack(fill="x", pady=(4, 4))
        self.table.update_rows(rows)
        self.table.pack(fill="both", expand=True, padx=16, pady=8)

    def get_rows(self):
        return self._rows

    def update_texts(self):
        self.title_lbl.configure(text=t("hashes_header"))
        if self._file_path:
            self.lbl_file.configure(text=f"{t('file_prefix')}{os.path.basename(self._file_path)}")
        else:
            self.lbl_file.configure(text=f"{t('file_prefix')}-")
        self.prompt_lbl.configure(text=t("hashes_calc_prompt"))
        self.desc_lbl.configure(text=t("hashes_calc_desc"))
        self.btn_calc.configure(text=t("btn_calculate"))
        self.btn_recalc.configure(text=t("btn_recalculate"))
        if self._rows is not None:
            self.table.update_rows(self._rows)


class MetaTab(ctk.CTkFrame):
    """Ansicht fuer formatspezifische Metadaten (wird sofort berechnet)."""

    def __init__(self, parent, on_calculated=None, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._file_path = None
        self._rows = []
        self._on_calculated = on_calculated

        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        self.title_lbl = make_label(self.header, t("meta_header"), font=FONT_HEAD, color=ACCENT)
        self.title_lbl.pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, f"{t('file_prefix')}-", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.spinner = make_label(self, t("meta_reading"), color=TXT_DIM)
        self.count_lbl = make_label(self, "", color=TXT_DIM, font=("Segoe UI", 12, "bold"))
        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str, cached_rows=None):
        self._file_path = file_path
        name = os.path.basename(file_path)
        self.lbl_file.configure(text=f"{t('file_prefix')}{name}")

        self.table.pack_forget()
        self.count_lbl.pack_forget()

        if cached_rows is not None:
            self._rows = cached_rows
            self._show(cached_rows)
            return

        self.spinner.configure(text=t("meta_reading"))
        self.spinner.pack(pady=20)

        def _load():
            result = metadata.get_all(file_path)
            rows = list(result.items())
            self._rows = rows
            if self._on_calculated:
                self._on_calculated(file_path, rows)
            self.after(0, lambda: self._show(rows))

        threading.Thread(target=_load, daemon=True).start()

    def _show(self, rows):
        self.spinner.pack_forget()
        self.count_lbl.configure(text=t("meta_found", count=len(rows)))
        self.count_lbl.pack(anchor="w", padx=20, pady=(0, 4))
        self.table.update_rows(rows)
        self.table.pack(fill="both", expand=True, padx=16, pady=8)

    def get_rows(self):
        return self._rows

    def update_texts(self):
        self.title_lbl.configure(text=t("meta_header"))
        if self._file_path:
            self.lbl_file.configure(text=f"{t('file_prefix')}{os.path.basename(self._file_path)}")
        else:
            self.lbl_file.configure(text=f"{t('file_prefix')}-")
        if self._rows:
            self.count_lbl.configure(text=t("meta_found", count=len(self._rows)))
            self.table.update_rows(self._rows)


class InfoTab(ctk.CTkFrame):
    """Ansicht fuer Dateisystem- und Rechte-Informationen."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._file_path = None
        self._raw_info = {}

        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        self.title_lbl = make_label(self.header, t("info_header"), font=FONT_HEAD, color=ACCENT)
        self.title_lbl.pack(anchor="w", padx=16, pady=10)
        self.lbl_file = make_label(self.header, f"{t('file_prefix')}-", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str, cached_raw=None):
        self._file_path = file_path
        name = os.path.basename(file_path)
        self.lbl_file.configure(text=f"{t('file_prefix')}{name}")
        self.table.pack_forget()

        if cached_raw is not None:
            self._raw_info = cached_raw
        else:
            self._raw_info = fileinfo.get_all(file_path)

        self._render_rows()

    def _render_rows(self):
        if not self._raw_info:
            return
        
        mapping = [
            (t("info_filename"), self._raw_info.get("Dateiname", "")),
            (t("info_extension"), self._raw_info.get("Erweiterung", "")),
            (t("info_mimetype"), self._raw_info.get("MIME-Typ", "")),
            (t("info_abspath"), self._raw_info.get("Absoluter Pfad", "")),
            (t("info_dir"), self._raw_info.get("Verzeichnis", "")),
            (t("info_drive"), self._raw_info.get("Laufwerk", "")),
            (t("info_size"), self._raw_info.get("Dateigröße", "")),
            (t("info_size_raw"), self._raw_info.get("Dateigröße (raw Bytes)", "")),
            (t("info_ctime"), self._raw_info.get("Erstellungsdatum (ctime)", "")),
            (t("info_mtime"), self._raw_info.get("Änderungsdatum (mtime)", "")),
            (t("info_atime"), self._raw_info.get("Letzter Zugriff (atime)", "")),
            (t("info_perms_octal"), self._raw_info.get("Zugriffsrechte (octal)", "")),
            (t("info_perms_rwx"), self._raw_info.get("Zugriffsrechte (rwx)", "")),
            (t("info_readable"), t("yes") if self._raw_info.get("Lesbar") == "Ja" else t("no")),
            (t("info_writable"), t("yes") if self._raw_info.get("Schreibbar") == "Ja" else t("no")),
            (t("info_executable"), t("yes") if self._raw_info.get("Ausführbar") == "Ja" else t("no")),
            (t("info_owner_uid"), self._raw_info.get("Owner UID", "")),
            (t("info_group_gid"), self._raw_info.get("Gruppen GID", "")),
            (t("info_inode"), self._raw_info.get("Inode", "")),
            (t("info_hardlinks"), self._raw_info.get("Hardlinks", "")),
            (t("info_device"), self._raw_info.get("Gerät (Device ID)", "")),
        ]
        
        self.table.update_rows(mapping)
        self.table.pack(fill="both", expand=True, padx=16, pady=12)

    def get_raw_info(self):
        return self._raw_info

    def update_texts(self):
        self.title_lbl.configure(text=t("info_header"))
        if self._file_path:
            self.lbl_file.configure(text=f"{t('file_prefix')}{os.path.basename(self._file_path)}")
        else:
            self.lbl_file.configure(text=f"{t('file_prefix')}-")
        self._render_rows()


class VTTab(ctk.CTkFrame):
    """Ansicht fuer VirusTotal-Pruefung und AV-Ergebnisse."""

    def __init__(self, parent, on_scanned=None, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._file_path = None
        self._res = None
        self._on_scanned = on_scanned

        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        self.title_lbl = make_label(self.header, t("vt_header"), font=FONT_HEAD, color=ACCENT)
        self.title_lbl.pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, f"{t('file_prefix')}-", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.spinner = make_label(self, t("vt_connecting"), color=TXT_DIM)
        self.progress = ctk.CTkProgressBar(self, mode="indeterminate", progress_color=ACCENT, height=6)
        
        self.results_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._vt_widgets = []

    def load(self, file_path: str, cached_res=None):
        self._file_path = file_path
        name = os.path.basename(file_path)
        self.lbl_file.configure(text=f"{t('file_prefix')}{name}")
        self.results_frame.pack_forget()
        
        for w in self._vt_widgets:
            w.destroy()
        self._vt_widgets.clear()

        if cached_res is not None:
            self._res = cached_res
            self._show(cached_res)
            return

        self.spinner.configure(text=t("vt_connecting"))
        self.spinner.pack(pady=20)
        self.progress.pack(fill="x", padx=40, pady=8)
        self.progress.start()

        def _scan():
            res = virustotal.scan_file(file_path, VT_API_KEY, progress_callback=self._set_status)
            self._res = res
            if self._on_scanned:
                self._on_scanned(file_path, res)
            self.after(0, lambda: self._show(res))

        threading.Thread(target=_scan, daemon=True).start()

    def _set_status(self, msg: str):
        self.after(0, lambda: self.spinner.configure(text=f"{msg}"))

    def _show(self, res: dict):
        self.progress.stop()
        self.progress.pack_forget()
        self.spinner.pack_forget()

        self.results_frame.pack(fill="both", expand=True)

        if "error" in res:
            err_lbl = make_label(self.results_frame, t("vt_error", error=res['error']), color=WARN)
            err_lbl.pack(pady=20)
            self._vt_widgets.append(err_lbl)
            return

        stats = res.get("stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values()) or 1

        banner = make_card(self.results_frame)
        banner.pack(fill="x", padx=16, pady=(0, 12))
        self._vt_widgets.append(banner)

        verdict_color = DANGER if malicious > 0 else (WARN if suspicious > 0 else OK)
        verdict_text  = (t("vt_danger") if malicious > 0 else (t("vt_suspicious") if suspicious > 0 else t("vt_clean")))

        ctk.CTkLabel(banner, text=verdict_text, font=("Segoe UI", 20, "bold"), text_color=verdict_color).pack(anchor="w", padx=16, pady=(12, 4))

        stats_txt = (
            f"{t('vt_detected', detected=malicious + suspicious, total=total)}   |   "
            f"{t('vt_malicious', malicious=malicious)}   |   "
            f"{t('vt_suspicious_count', suspicious=suspicious)}   |   "
            f"{t('vt_undetected', undetected=undetected)}"
        )
        make_label(banner, stats_txt, color=TXT_DIM).pack(anchor="w", padx=16, pady=(0, 6))

        if res.get("permalink"):
            link_btn = ctk.CTkButton(
                banner, text=t("vt_open_report"),
                fg_color="transparent", hover_color=ACCENT_DIM,
                text_color=ACCENT, font=("Segoe UI", 11),
                command=lambda url=res["permalink"]: self._open_link(url)
            )
            link_btn.pack(anchor="w", padx=12, pady=(0, 10))

        engines = res.get("engines", [])
        rows = []
        for e in engines:
            cat = e.get("category", "")
            eresult = e.get("result", "-")
            prefix = f"[{cat.upper()}]" if cat else "[INFO]"
            rows.append((f"{prefix} {e['engine']}", f"{cat} - {eresult}"))

        if rows:
            lbl_res = make_label(
                self.results_frame, t("vt_scanner_results", count=len(rows)),
                font=("Segoe UI", 12, "bold"), color=TXT_DIM
            )
            lbl_res.pack(anchor="w", padx=20, pady=(4, 2))
            self._vt_widgets.append(lbl_res)
            
            table = DataTable(self.results_frame, rows=rows, copyable=False, height=380)
            table.pack(fill="both", expand=True, padx=16, pady=(0, 12))
            self._vt_widgets.append(table)

    def _open_link(self, url: str):
        import webbrowser
        webbrowser.open(url)

    def get_res(self):
        return self._res

    def update_texts(self):
        self.title_lbl.configure(text=t("vt_header"))
        if self._file_path:
            self.lbl_file.configure(text=f"{t('file_prefix')}{os.path.basename(self._file_path)}")
        else:
            self.lbl_file.configure(text=f"{t('file_prefix')}-")
        if self._res:
            for w in self._vt_widgets:
                w.destroy()
            self._vt_widgets.clear()
            self._show(self._res)


class CompareTab(ctk.CTkFrame):
    """Ansicht zum Gegenueberstellen und Vergleichen zweier geoeffneter Dateien."""

    def __init__(self, parent, get_all_sessions, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._get_all_sessions = get_all_sessions
        self._file_a = None
        self._file_b = None

        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        self.title_lbl = make_label(self.header, t("compare_header"), font=FONT_HEAD, color=ACCENT)
        self.title_lbl.pack(anchor="w", padx=16, pady=10)

        self.select_card = make_card(self)
        self.select_card.pack(fill="x", padx=16, pady=12)

        self.hint_lbl = make_label(self.select_card, t("compare_select_hint"), color=TXT_DIM)
        self.hint_lbl.pack(anchor="w", padx=16, pady=(12, 8))

        row_sel = ctk.CTkFrame(self.select_card, fg_color="transparent")
        row_sel.pack(fill="x", padx=16, pady=(0, 12))

        self.lbl_a = make_label(row_sel, f"{t('compare_file_a')}:", font=("Segoe UI", 11, "bold"))
        self.lbl_a.pack(side="left", padx=(0, 6))
        self.opt_a = ctk.CTkOptionMenu(row_sel, values=["-"], command=self._on_select_a, width=240, fg_color=BG_ROW_B, button_color=ACCENT_DIM)
        self.opt_a.pack(side="left", padx=(0, 20))

        self.lbl_b = make_label(row_sel, f"{t('compare_file_b')}:", font=("Segoe UI", 11, "bold"))
        self.lbl_b.pack(side="left", padx=(0, 6))
        self.opt_b = ctk.CTkOptionMenu(row_sel, values=["-"], command=self._on_select_b, width=240, fg_color=BG_ROW_B, button_color=ACCENT_DIM)
        self.opt_b.pack(side="left", padx=(0, 20))

        self.btn_compare = ctk.CTkButton(
            row_sel, text=t("compare_btn"), font=("Segoe UI", 11, "bold"),
            fg_color=ACCENT, hover_color=ACCENT_DIM, command=self._run_compare
        )
        self.btn_compare.pack(side="left", padx=10)

        self.verdict_card = make_card(self)
        self.verdict_lbl = make_label(self.verdict_card, "", font=("Segoe UI", 15, "bold"))
        self.verdict_lbl.pack(padx=16, pady=10)

        self.table = DataTable(self, rows=[], copyable=True, height=420)

    def refresh_options(self):
        sessions = self._get_all_sessions()
        file_paths = [s.file_path for s in sessions if s.file_path]
        filenames = [os.path.basename(p) for p in file_paths]

        if not filenames:
            self.opt_a.configure(values=["-"])
            self.opt_b.configure(values=["-"])
            self.opt_a.set("-")
            self.opt_b.set("-")
            self.verdict_card.pack_forget()
            self.table.pack_forget()
            return

        self.opt_a.configure(values=filenames)
        self.opt_b.configure(values=filenames)

        if len(filenames) >= 1:
            self.opt_a.set(filenames[0])
            self._file_a = file_paths[0]
        if len(filenames) >= 2:
            self.opt_b.set(filenames[1])
            self._file_b = file_paths[1]
        else:
            self.opt_b.set(filenames[0])
            self._file_b = file_paths[0]

        self._run_compare()

    def _on_select_a(self, choice):
        sessions = self._get_all_sessions()
        for s in sessions:
            if s.file_path and os.path.basename(s.file_path) == choice:
                self._file_a = s.file_path
                break
        self._run_compare()

    def _on_select_b(self, choice):
        sessions = self._get_all_sessions()
        for s in sessions:
            if s.file_path and os.path.basename(s.file_path) == choice:
                self._file_b = s.file_path
                break
        self._run_compare()

    def _run_compare(self):
        if not self._file_a or not self._file_b:
            self.verdict_card.pack_forget()
            self.table.pack_forget()
            return

        name_a = os.path.basename(self._file_a)
        name_b = os.path.basename(self._file_b)

        info_a = fileinfo.get_all(self._file_a)
        info_b = fileinfo.get_all(self._file_b)
        hash_a = hashes.compute_all(self._file_a)
        hash_b = hashes.compute_all(self._file_b)

        sha256_match = (hash_a.get("SHA-256") == hash_b.get("SHA-256"))
        
        self.verdict_card.pack(fill="x", padx=16, pady=(0, 10))
        if sha256_match:
            self.verdict_lbl.configure(
                text=f"[MATCH] {t('compare_identical')}",
                text_color=OK
            )
        else:
            self.verdict_lbl.configure(
                text=f"[DIFF] {t('compare_different')}",
                text_color=DANGER
            )

        rows = []
        props = [
            (t("info_filename"), name_a, name_b),
            (t("info_size"), info_a.get("Dateigröße"), info_b.get("Dateigröße")),
            (t("info_size_raw"), info_a.get("Dateigröße (raw Bytes)"), info_b.get("Dateigröße (raw Bytes)")),
            (t("info_mimetype"), info_a.get("MIME-Typ"), info_b.get("MIME-Typ")),
            ("MD5", hash_a.get("MD5"), hash_b.get("MD5")),
            ("SHA-1", hash_a.get("SHA-1"), hash_b.get("SHA-1")),
            ("SHA-256", hash_a.get("SHA-256"), hash_b.get("SHA-256")),
            ("SHA-512", hash_a.get("SHA-512"), hash_b.get("SHA-512")),
            (t("info_mtime"), info_a.get("Änderungsdatum (mtime)"), info_b.get("Änderungsdatum (mtime)")),
            (t("info_ctime"), info_a.get("Erstellungsdatum (ctime)"), info_b.get("Erstellungsdatum (ctime)")),
        ]

        for prop_name, val_a, val_b in props:
            match = (str(val_a) == str(val_b))
            tag = "[OK]" if match else "[DIFF]"
            status_text = t("compare_match") if match else t("compare_diff")
            
            key_col = f"{tag} {prop_name}"
            val_col = f"[{name_a}]: {val_a}\n[{name_b}]: {val_b}  ({status_text})"
            rows.append((key_col, val_col))

        self.table.update_rows(rows, copyable=True)
        self.table.pack(fill="both", expand=True, padx=16, pady=8)

    def update_texts(self):
        self.title_lbl.configure(text=t("compare_header"))
        self.hint_lbl.configure(text=t("compare_select_hint"))
        self.lbl_a.configure(text=f"{t('compare_file_a')}:")
        self.lbl_b.configure(text=f"{t('compare_file_b')}:")
        self.btn_compare.configure(text=t("compare_btn"))
        if self._file_a and self._file_b:
            self._run_compare()


class UploadView(ctk.CTkFrame):
    """Start- und Dateiauswahl-Ansicht."""

    def __init__(self, parent, on_file_selected, start_screen=False, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._on_file = on_file_selected
        self._start = start_screen
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()

        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        card = make_card(wrapper)
        card.pack(padx=40, pady=40)

        if self._start:
            self.title_l = ctk.CTkLabel(card, text="HashyMime", font=("Segoe UI", 32, "bold"), text_color=ACCENT)
            self.title_l.pack(pady=(30, 4))
            self.sub_l = ctk.CTkLabel(card, text=t("app_subtitle"), font=("Segoe UI", 13), text_color=TXT_DIM)
            self.sub_l.pack(pady=(0, 20))
        else:
            self.title_l = ctk.CTkLabel(card, text=t("upload_title"), font=("Segoe UI", 22, "bold"), text_color=TXT)
            self.title_l.pack(pady=(30, 10))
            self.sub_l = ctk.CTkLabel(card, text=t("upload_subtitle"), font=("Segoe UI", 12), text_color=TXT_DIM)
            self.sub_l.pack(pady=(0, 20))

        drop_zone = ctk.CTkFrame(card, fg_color=BG_MAIN, corner_radius=12, border_width=2, border_color=ACCENT_DIM, width=380, height=140)
        drop_zone.pack(padx=30, pady=(0, 20))
        drop_zone.pack_propagate(False)
        self.lbl_drop = ctk.CTkLabel(drop_zone, text=t("drop_title"), font=("Segoe UI", 16, "bold"), text_color=TXT)
        self.lbl_drop.pack(pady=(45, 4))

        self.upload_btn = ctk.CTkButton(
            card, text=t("btn_open"), font=("Segoe UI", 14, "bold"),
            fg_color=ACCENT, hover_color=ACCENT_DIM, height=48, corner_radius=10, width=240,
            command=self._browse
        )
        self.upload_btn.pack(pady=(0, 30))

        for w in [drop_zone, self.lbl_drop]:
            w.bind("<ButtonRelease-1>", lambda e: self._browse())

    def _browse(self):
        self.winfo_toplevel().after(10, self._open_dialog)

    def _open_dialog(self):
        path = filedialog.askopenfilename(title=t("open_dialog_title"))
        if path:
            self._on_file(path)

    def update_texts(self):
        if self._start:
            self.sub_l.configure(text=t("app_subtitle"))
        else:
            self.title_l.configure(text=t("upload_title"))
            self.sub_l.configure(text=t("upload_subtitle"))
        self.lbl_drop.configure(text=t("drop_title"))
        self.upload_btn.configure(text=t("btn_open"))


class FileSession:
    """Repraesentiert den Zustand einer geoeffneten Datei in einem Browser-Tab."""

    def __init__(self, session_id: int, file_path: str):
        self.session_id = session_id
        self.file_path = file_path
        self.hash_rows = None  # None bedeutet: Hashes noch nicht errechnet!
        self.meta_rows = None
        self.raw_info = None
        self.vt_res = None
        self.active_subview = 0


class HashyMime(ctk.CTk):
    """Hauptanwendungsfenster fuer HashyMime mit Browser-Tabs und Mehrsprachigkeit."""

    def __init__(self):
        super().__init__()
        self.title("HashyMime")
        self.geometry("1120x760")
        self.minsize(940, 640)
        self.configure(fg_color=BG_MAIN)

        self._sessions: list[FileSession] = []
        self._active_session_id = None
        self._next_session_id = 1
        self._current_subview = 0

        self._build_ui()

    def _build_ui(self):
        # 1. Kopfzeile mit Logo, Dateistatus & Sprachauswahl
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=56, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Links: Logo & Dateistatus
        left_header = ctk.CTkFrame(header, fg_color="transparent")
        left_header.pack(side="left", padx=16, pady=8)

        self._app_title_lbl = ctk.CTkLabel(
            left_header, text="HashyMime", font=("Segoe UI", 18, "bold"), text_color=ACCENT
        )
        self._app_title_lbl.pack(side="left", padx=(0, 12))

        self._file_badge = ctk.CTkLabel(
            left_header, text=t("no_file"), font=("Segoe UI", 11), text_color=TXT_DIM
        )
        self._file_badge.pack(side="left")

        # Rechts: Sprachauswahl (Dropdown)
        right_header = ctk.CTkFrame(header, fg_color="transparent")
        right_header.pack(side="right", padx=16, pady=8)

        self._lang_title_lbl = ctk.CTkLabel(
            right_header, text=t("lang_label"), font=("Segoe UI", 11, "bold"), text_color=TXT_DIM
        )
        self._lang_title_lbl.pack(side="left", padx=(0, 8))

        self._lang_menu = ctk.CTkOptionMenu(
            right_header,
            values=["Deutsch", "English", "Français", "Español"],
            command=self._on_language_change,
            width=115, height=30,
            fg_color=BG_ROW_B, button_color=ACCENT_DIM,
            button_hover_color=ACCENT, text_color=TXT,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TXT,
            dropdown_hover_color=BG_ROW_A, font=("Segoe UI", 11, "bold")
        )
        self._lang_menu.set("Deutsch")
        self._lang_menu.pack(side="left")

        # 2. Browser Tab-Leiste
        self._tab_bar = BrowserTabBar(
            self,
            on_tab_switch=self._switch_to_session,
            on_tab_close=self._close_session,
            on_new_tab=self._prompt_new_tab
        )
        self._tab_bar.pack(fill="x", padx=0, pady=(0, 0))

        # 3. Navigationsleiste (Breadcrumbs)
        self._crumbs = Breadcrumbs(self, on_select=self._switch_subview)
        self._crumbs.pack(fill="x", padx=16, pady=(10, 0))
        self._crumbs.set_enabled(False)

        # 4. Haupt-Inhaltsbereich
        self._content = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._content.pack(fill="both", expand=True, padx=0, pady=0)

        # Unteransichten
        self._hash_tab = HashTab(self._content, on_calculated=self._on_hashes_calculated)
        self._meta_tab = MetaTab(self._content, on_calculated=self._on_metadata_calculated)
        self._info_tab = InfoTab(self._content)
        self._vt_tab = VTTab(self._content, on_scanned=self._on_vt_scanned)
        self._compare_tab = CompareTab(self._content, get_all_sessions=lambda: self._sessions)
        self._start_view = UploadView(self._content, on_file_selected=self._on_file_loaded, start_screen=True)

        self._show_start()

    def _on_language_change(self, selected_lang_name: str):
        i18n.set_language(selected_lang_name)
        
        active_session = self._get_active_session()
        if active_session:
            name = os.path.basename(active_session.file_path)
            self._file_badge.configure(text=f"{t('file_prefix')}{name}")
        else:
            self._file_badge.configure(text=t("no_file"))

        self._lang_title_lbl.configure(text=t("lang_label"))
        self._crumbs.update_texts()
        self._hash_tab.update_texts()
        self._meta_tab.update_texts()
        self._info_tab.update_texts()
        self._vt_tab.update_texts()
        self._compare_tab.update_texts()
        self._start_view.update_texts()

    def _show_start(self):
        self._hide_all_tabs()
        self._file_badge.configure(text=t("no_file"), text_color=TXT_DIM)
        self._crumbs.set_enabled(False)
        self._start_view.pack(fill="both", expand=True)

    def _hide_all_tabs(self):
        self._start_view.pack_forget()
        self._hash_tab.pack_forget()
        self._meta_tab.pack_forget()
        self._info_tab.pack_forget()
        self._vt_tab.pack_forget()
        self._compare_tab.pack_forget()

    def _get_active_session(self) -> FileSession | None:
        for s in self._sessions:
            if s.session_id == self._active_session_id:
                return s
        return None

    def _on_file_loaded(self, path: str):
        for s in self._sessions:
            if s.file_path == path:
                self._switch_to_session(s.session_id)
                return

        new_session = FileSession(self._next_session_id, path)
        self._next_session_id += 1
        self._sessions.append(new_session)
        self._active_session_id = new_session.session_id

        self._update_tab_bar()
        self._load_active_session()

    def _prompt_new_tab(self):
        path = filedialog.askopenfilename(title=t("open_dialog_title"))
        if path:
            self._on_file_loaded(path)

    def _update_tab_bar(self):
        tabs_data = []
        for s in self._sessions:
            name = os.path.basename(s.file_path)
            tabs_data.append((s.session_id, name, s.file_path))
        self._tab_bar.set_tabs(tabs_data, self._active_session_id)

        has_multiple = len(self._sessions) >= 2
        self._crumbs.set_show_compare(has_multiple)

    def _switch_to_session(self, session_id: int):
        self._active_session_id = session_id
        self._update_tab_bar()
        self._load_active_session()

    def _close_session(self, session_id: int):
        idx_to_remove = None
        for i, s in enumerate(self._sessions):
            if s.session_id == session_id:
                idx_to_remove = i
                break

        if idx_to_remove is not None:
            self._sessions.pop(idx_to_remove)

        if not self._sessions:
            self._active_session_id = None
            self._update_tab_bar()
            self._show_start()
        else:
            new_idx = min(idx_to_remove, len(self._sessions) - 1)
            self._active_session_id = self._sessions[new_idx].session_id
            self._update_tab_bar()
            self._load_active_session()

    def _load_active_session(self):
        session = self._get_active_session()
        if not session:
            self._show_start()
            return

        name = os.path.basename(session.file_path)
        self._file_badge.configure(text=f"{t('file_prefix')}{name}", text_color=TXT)
        self._crumbs.set_enabled(True)

        # Hashes bleiben On-Demand (cached oder Aufforderung)
        self._hash_tab.load(session.file_path, cached_rows=session.hash_rows)
        # Metadaten werden sofort berechnet
        self._meta_tab.load(session.file_path, cached_rows=session.meta_rows)
        self._info_tab.load(session.file_path, cached_raw=session.raw_info)
        self._vt_tab.load(session.file_path, cached_res=session.vt_res)

        self._switch_subview(session.active_subview)
        self._crumbs.select(session.active_subview)

    def _switch_subview(self, idx: int):
        session = self._get_active_session()
        if session:
            session.active_subview = idx
            if session.meta_rows is None and self._meta_tab.get_rows():
                session.meta_rows = self._meta_tab.get_rows()
            if session.raw_info is None and self._info_tab.get_raw_info():
                session.raw_info = self._info_tab.get_raw_info()

        self._hide_all_tabs()

        if idx == 0:
            self._hash_tab.pack(fill="both", expand=True)
        elif idx == 1:
            self._meta_tab.pack(fill="both", expand=True)
        elif idx == 2:
            self._info_tab.pack(fill="both", expand=True)
        elif idx == 3:
            self._vt_tab.pack(fill="both", expand=True)
        elif idx == 4:
            if len(self._sessions) >= 2:
                self._compare_tab.refresh_options()
                self._compare_tab.pack(fill="both", expand=True)
            else:
                self._hash_tab.pack(fill="both", expand=True)

    def _on_hashes_calculated(self, file_path: str, rows: list):
        for s in self._sessions:
            if s.file_path == file_path:
                s.hash_rows = rows
                break

    def _on_metadata_calculated(self, file_path: str, rows: list):
        for s in self._sessions:
            if s.file_path == file_path:
                s.meta_rows = rows
                break

    def _on_vt_scanned(self, file_path: str, res: dict):
        for s in self._sessions:
            if s.file_path == file_path:
                s.vt_res = res
                break


if __name__ == "__main__":
    app = HashyMime()
    app.mainloop()
