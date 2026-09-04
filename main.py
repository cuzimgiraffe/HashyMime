"""HashyMime - Desktop-Anwendung zur Datei-Analyse und Forensik."""

import os
import threading
from tkinter import filedialog
import customtkinter as ctk
from dotenv import load_dotenv

from modules import hashes, metadata, fileinfo, virustotal

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Farb- und Layoutkonfiguration.
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

ACCENT     = "#00BFA5"
ACCENT_DIM = "#007A6B"
BG_CARD    = "#1E1E2E"
BG_MAIN    = "#12121C"
BG_ROW_A   = "#1A1A2A"
BG_ROW_B   = "#1E1E30"
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


def copy_to_clipboard(root: ctk.CTk, text: str):
    # Kopiert Text in die Zwischenablage.
    root.clipboard_clear()
    root.clipboard_append(text)


def make_card(parent, **kwargs) -> ctk.CTkFrame:
    # Erstellt einen einheitlichen Karten-Container.
    return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12, **kwargs)


def make_label(parent, text, font=None, color=TXT, **kwargs) -> ctk.CTkLabel:
    # Erstellt ein einheitlich formatiertes Textlabel.
    return ctk.CTkLabel(parent, text=text, font=font or FONT_LABEL,
                        text_color=color, **kwargs)


class DataTable(ctk.CTkScrollableFrame):
    """Scrollbare Key-Value Tabelle mit integriertem Kopier-Button."""

    def __init__(self, parent, rows: list[tuple], copyable=True, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._build(rows, copyable)

    def _copy(self, text):
        self.winfo_toplevel().clipboard_clear()
        self.winfo_toplevel().clipboard_append(text)

    def _build(self, rows, copyable):
        if hasattr(self, "_row_widgets"):
            for w in self._row_widgets:
                w.destroy()
        self._row_widgets = []

        self.grid_columnconfigure(1, weight=1)

        for i, (key, val) in enumerate(rows):
            bg = BG_ROW_A if i % 2 == 0 else BG_ROW_B
            
            lbl_key = ctk.CTkLabel(self, text=key, font=("Segoe UI", 11, "bold"), text_color=ACCENT, anchor="w", width=220, fg_color=bg, corner_radius=6)
            lbl_key.grid(row=i, column=0, padx=(10, 6), pady=2, sticky="nsew")
            
            lbl_val = ctk.CTkLabel(self, text=str(val), font=FONT_MONO, text_color=TXT, anchor="w", wraplength=500, fg_color=bg, corner_radius=6)
            lbl_val.grid(row=i, column=1, padx=4, pady=2, sticky="nsew")
            
            self._row_widgets.extend([lbl_key, lbl_val])

            if copyable:
                btn = ctk.CTkButton(self, text="Copy", width=50, height=24, fg_color=BG_ROW_B, hover_color=ACCENT_DIM, command=lambda v=str(val): self._copy(v))
                btn.grid(row=i, column=2, padx=(6, 10), pady=2)
                self._row_widgets.append(btn)

    def update_rows(self, rows, copyable=True):
        self._build(rows, copyable)


CRUMBS = ["Hash", "Metadaten", "Datei-Infos", "VirusTotal", "Upload"]


class Breadcrumbs(ctk.CTkFrame):
    """Navigationsleiste fuer die Ansichten."""

    def __init__(self, parent, on_select, **kwargs):
        super().__init__(parent, fg_color=BG_CARD, corner_radius=10, **kwargs)
        self._on_select = on_select
        self._active = 0
        self._btns = []
        self._build()

    def _build(self):
        for i, name in enumerate(CRUMBS):
            if i > 0:
                ctk.CTkLabel(self, text=">", font=("Segoe UI", 14),
                             text_color=TXT_DIM).pack(side="left", padx=2)

            btn = ctk.CTkButton(
                self, text=name, font=FONT_CRUMB,
                fg_color="transparent", hover_color=ACCENT_DIM,
                text_color=TXT_DIM, corner_radius=8,
                width=110, height=36,
                command=lambda idx=i: self.select(idx)
            )
            btn.pack(side="left", padx=2, pady=6)
            self._btns.append(btn)

        self._highlight(0)

    def _highlight(self, idx: int):
        for i, btn in enumerate(self._btns):
            if i == idx:
                btn.configure(fg_color=ACCENT, text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=TXT_DIM)

    def select(self, idx: int):
        self._active = idx
        self._highlight(idx)
        self._on_select(idx)

    def set_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for btn in self._btns:
            btn.configure(state=state)


class HashTab(ctk.CTkFrame):
    """Ansicht fuer kryptographische Hash-Werte."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        
        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        make_label(self.header, "Kryptographische Hashes", font=FONT_HEAD, color=ACCENT).pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, "Datei: -", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))
        
        self.spinner = make_label(self, "Berechne Hashes...", color=TXT_DIM)
        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str):
        self.lbl_file.configure(text=f"Datei: {os.path.basename(file_path)}")
        self.table.pack_forget()
        self.spinner.pack(pady=20)

        def _compute():
            result = hashes.compute_all(file_path)
            rows = list(result.items())
            self.after(0, lambda: self._show(rows))

        threading.Thread(target=_compute, daemon=True).start()

    def _show(self, rows):
        self.spinner.pack_forget()
        self.table.update_rows(rows)
        self.table.pack(fill="both", expand=True, padx=16, pady=12)


class MetaTab(ctk.CTkFrame):
    """Ansicht fuer formatspezifische Metadaten."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        
        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        make_label(self.header, "Metadaten", font=FONT_HEAD, color=ACCENT).pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, "Datei: -", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.spinner = make_label(self, "Lese Metadaten...", color=TXT_DIM)
        self.count_lbl = make_label(self, "", color=TXT_DIM)
        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str):
        self.lbl_file.configure(text=f"Datei: {os.path.basename(file_path)}")
        self.table.pack_forget()
        self.count_lbl.pack_forget()
        self.spinner.pack(pady=20)

        def _load():
            result = metadata.get_all(file_path)
            rows = list(result.items())
            self.after(0, lambda: self._show(rows))

        threading.Thread(target=_load, daemon=True).start()

    def _show(self, rows):
        self.spinner.pack_forget()
        self.count_lbl.configure(text=f"{len(rows)} Metadaten gefunden")
        self.count_lbl.pack(anchor="w", padx=20, pady=(0, 4))
        self.table.update_rows(rows)
        self.table.pack(fill="both", expand=True, padx=16, pady=8)


class InfoTab(ctk.CTkFrame):
    """Ansicht fuer Dateisystem- und Rechte-Informationen."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        
        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        make_label(self.header, "Datei-Informationen", font=FONT_HEAD, color=ACCENT).pack(anchor="w", padx=16, pady=10)
        self.lbl_file = make_label(self.header, "Datei: -", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.table = DataTable(self, rows=[], height=500)

    def load(self, file_path: str):
        self.lbl_file.configure(text=f"Datei: {os.path.basename(file_path)}")
        self.table.pack_forget()
        result = fileinfo.get_all(file_path)
        rows = list(result.items())
        self.table.update_rows(rows)
        self.table.pack(fill="both", expand=True, padx=16, pady=12)


class VTTab(ctk.CTkFrame):
    """Ansicht fuer VirusTotal-Pruefung und AV-Ergebnisse."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        
        self.header = make_card(self)
        self.header.pack(fill="x", padx=16, pady=(16, 0))
        make_label(self.header, "VirusTotal Scan", font=FONT_HEAD, color=ACCENT).pack(anchor="w", padx=16, pady=10)
        
        self.lbl_file = make_label(self.header, "Datei: -", color=TXT_DIM)
        self.lbl_file.pack(anchor="w", padx=16, pady=(0, 10))

        self.spinner = make_label(self, "Verbinde mit VirusTotal...", color=TXT_DIM)
        self.progress = ctk.CTkProgressBar(self, mode="indeterminate", progress_color=ACCENT, height=6)
        
        self.results_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._vt_widgets = []

    def load(self, file_path: str):
        self.lbl_file.configure(text=f"Datei: {os.path.basename(file_path)}")
        self.results_frame.pack_forget()
        
        for w in self._vt_widgets:
            w.destroy()
        self._vt_widgets.clear()
            
        self.spinner.configure(text="Verbinde mit VirusTotal...")
        self.spinner.pack(pady=20)
        self.progress.pack(fill="x", padx=40, pady=8)
        self.progress.start()

        def _scan():
            res = virustotal.scan_file(file_path, VT_API_KEY, progress_callback=self._set_status)
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
            err_lbl = make_label(self.results_frame, f"Fehler: {res['error']}", color=WARN)
            err_lbl.pack(pady=20)
            self._vt_widgets.append(err_lbl)
            return

        stats = res.get("stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = sum(stats.values())

        banner = make_card(self.results_frame)
        banner.pack(fill="x", padx=16, pady=(0, 12))
        self._vt_widgets.append(banner)

        verdict_color = DANGER if malicious > 0 else (WARN if suspicious > 0 else OK)
        verdict_text  = ("GEFAEHRLICH" if malicious > 0 else ("VERDAECHTIG" if suspicious > 0 else "SAUBER"))

        ctk.CTkLabel(banner, text=verdict_text, font=("Segoe UI", 20, "bold"), text_color=verdict_color).pack(anchor="w", padx=16, pady=(12, 4))

        stats_txt = (f"Detektiert: {malicious + suspicious}/{total}   |   "
                     f"Malicious: {malicious}   |   Suspicious: {suspicious}   |   "
                     f"Undetected: {undetected}")
        make_label(banner, stats_txt, color=TXT_DIM).pack(anchor="w", padx=16, pady=(0, 6))

        if res.get("permalink"):
            link_btn = ctk.CTkButton(banner, text="VirusTotal Bericht oeffnen",
                                     fg_color="transparent", hover_color=ACCENT_DIM,
                                     text_color=ACCENT, font=("Segoe UI", 11),
                                     command=lambda url=res["permalink"]: self._open_link(url))
            link_btn.pack(anchor="w", padx=12, pady=(0, 10))

        engines = res.get("engines", [])
        rows = []
        for e in engines:
            cat = e.get("category", "")
            eresult = e.get("result", "-")
            prefix = f"[{cat.upper()}]" if cat else "[INFO]"
            rows.append((f"{prefix} {e['engine']}", f"{cat} - {eresult}"))

        if rows:
            lbl_res = make_label(self.results_frame, f"Scanner-Ergebnisse ({len(rows)})",
                                 font=("Segoe UI", 12, "bold"), color=TXT_DIM)
            lbl_res.pack(anchor="w", padx=20, pady=(4, 2))
            self._vt_widgets.append(lbl_res)
            
            table = DataTable(self.results_frame, rows=rows, copyable=False, height=380)
            table.pack(fill="both", expand=True, padx=16, pady=(0, 12))
            self._vt_widgets.append(table)

    def _open_link(self, url: str):
        import webbrowser
        webbrowser.open(url)


class UploadView(ctk.CTkFrame):
    """Start- und Dateiauswahl-Ansicht."""

    def __init__(self, parent, on_file_selected, start_screen=False, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, **kwargs)
        self._on_file = on_file_selected
        self._start = start_screen
        self._build()

    def _build(self):
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        card = make_card(wrapper)
        card.pack(padx=40, pady=40)

        if self._start:
            ctk.CTkLabel(card, text="HashyMime", font=("Segoe UI", 32, "bold"), text_color=ACCENT).pack(pady=(30, 4))
            ctk.CTkLabel(card, text="Datei-Forensik und Metadaten-Analyse", font=("Segoe UI", 13), text_color=TXT_DIM).pack(pady=(0, 20))
        else:
            ctk.CTkLabel(card, text="Neue Datei laden", font=("Segoe UI", 22, "bold"), text_color=TXT).pack(pady=(30, 10))
            ctk.CTkLabel(card, text="Waehle eine andere Datei zur Analyse.", font=("Segoe UI", 12), text_color=TXT_DIM).pack(pady=(0, 20))

        drop_zone = ctk.CTkFrame(card, fg_color=BG_MAIN, corner_radius=12, border_width=2, border_color=ACCENT_DIM, width=380, height=140)
        drop_zone.pack(padx=30, pady=(0, 20))
        drop_zone.pack_propagate(False)
        lbl1 = ctk.CTkLabel(drop_zone, text="Datei auswaehlen", font=("Segoe UI", 16, "bold"), text_color=TXT)
        lbl1.pack(pady=(45, 4))

        upload_btn = ctk.CTkButton(card, text="Datei oeffnen", font=("Segoe UI", 14, "bold"), fg_color=ACCENT, hover_color=ACCENT_DIM, height=48, corner_radius=10, width=240, command=self._browse)
        upload_btn.pack(pady=(0, 30))

        for w in [drop_zone, lbl1]:
            w.bind("<ButtonRelease-1>", lambda e: self._browse())

    def _browse(self):
        # Oeffnet den Dateidialog verzoegert fuer saubere Animationen.
        self.winfo_toplevel().after(10, self._open_dialog)

    def _open_dialog(self):
        path = filedialog.askopenfilename(title="Datei auswaehlen")
        if path:
            self._on_file(path)


class HashyMime(ctk.CTk):
    """Hauptanwendungsfenster fuer HashyMime."""

    def __init__(self):
        super().__init__()
        self.title("HashyMime")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(fg_color=BG_MAIN)
        self._file_path = None
        self._build_ui()

    def _build_ui(self):
        # Kopfzeile
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=60, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="HashyMime", font=("Segoe UI", 18, "bold"), text_color=ACCENT).pack(side="left", padx=20, pady=10)

        self._file_badge = ctk.CTkLabel(header, text="Keine Datei geladen", font=("Segoe UI", 11), text_color=TXT_DIM)
        self._file_badge.pack(side="left", padx=10)

        # Navigationsleiste
        self._crumbs = Breadcrumbs(self, on_select=self._switch_tab)
        self._crumbs.pack(fill="x", padx=16, pady=(12, 0))
        self._crumbs.set_enabled(False)

        # Inhaltsbereich
        self._content = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._content.pack(fill="both", expand=True, padx=0, pady=0)

        # Instanziiert alle Ansichten einmalig.
        self._tabs = {
            0: HashTab(self._content),
            1: MetaTab(self._content),
            2: InfoTab(self._content),
            3: VTTab(self._content),
            4: UploadView(self._content, on_file_selected=self._on_file_loaded, start_screen=False),
        }
        self._start_view = UploadView(self._content, on_file_selected=self._on_file_loaded, start_screen=True)
        
        self._show_start()

    def _show_start(self):
        for tab in self._tabs.values():
            tab.pack_forget()
        self._start_view.pack(fill="both", expand=True)

    def _on_file_loaded(self, path: str):
        self._file_path = path
        name = os.path.basename(path)
        self._file_badge.configure(text=f"Datei: {name}", text_color=TXT)

        self._start_view.pack_forget()

        # Datenanalyse in allen Tabs starten.
        self._tabs[0].load(path)
        self._tabs[1].load(path)
        self._tabs[2].load(path)
        self._tabs[3].load(path)

        self._crumbs.set_enabled(True)
        self._crumbs.select(0)

    def _switch_tab(self, idx: int):
        self._start_view.pack_forget()
        for tab in self._tabs.values():
            tab.pack_forget()
            
        tab = self._tabs.get(idx)
        if tab:
            tab.pack(fill="both", expand=True)


if __name__ == "__main__":
    app = HashyMime()
    app.mainloop()
