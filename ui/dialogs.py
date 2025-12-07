# ==============================================================================
# ui/dialogs.py
# Contiene componentes auxiliares de UI: Tooltips y diálogos
# ==============================================================================

import tkinter as tk
from tkinter import Toplevel, messagebox, simpledialog, font

class Tooltip:
    """
    Crea un tooltip (mensaje emergente) para un widget de tkinter.
    Extraído de SPYNET V3.5.1 (líneas ~200-220)
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        label = tk.Label(self.tooltip_window, text=self.text, justify='left',
                         background="#f0f0f0", relief='solid', borderwidth=1,
                         font=("Segoe UI", 8, "normal"))
        label.pack(ipadx=1)

    def hide_tooltip(self, event):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

def show_about_info():
    """
    Muestra la ventana 'Acerca de'.
    Extraído de SPYNET V3.5.1 (líneas ~1200)
    """
    messagebox.showinfo("Sobre SPYNET Beta V1.0",
                        "Analizador de Red\n\n"
                        "creado por HackCat.\n\n"
                        "Este proyecto utiliza Python, Tkinter, Scapy y Matplotlib, etc...\n\n"
                        "si encuentras alguna falla o quieres reportar algo comunicate a https://github.com/ever186.\n"
                        "¡Gracias por usar la herramienta!")

def configure_virustotal_api(controller):
    """
    Abre un diálogo para configurar la API de VirusTotal.
    Extraído de SPYNET V3.5.1 (líneas ~1410)
    """
    new_key = simpledialog.askstring("API Key de VirusTotal", "Introduce tu clave de API de VirusTotal:", parent=controller.window)
    if new_key:
        controller.virustotal_api_key = new_key
        messagebox.showinfo("Éxito", "Clave de API de VirusTotal guardada para esta sesión.")

def open_settings_window(controller):
    """
    Abre una ventana para configurar los puertos inseguros.
    Extraído de SPYNET V3.5.1 (líneas ~1170)
    """
    settings_window = Toplevel(controller.window)
    settings_window.title("Configuración")
    settings_window.geometry("400x150")
    settings_window.configure(bg="#34495e")
    settings_window.resizable(False, False)

    tk.Label(settings_window, text="Puertos Inseguros (separados por coma)", font=("Segoe UI", 10), bg="#34495e", fg="white").pack(pady=(10,5))
    
    ports_str = tk.StringVar(value=", ".join(map(str, controller.INSECURE_PORTS)))
    entry = tk.Entry(settings_window, textvariable=ports_str, width=50, bg="#2c3e50", fg="white")
    entry.pack(pady=5, padx=10)

    def save_settings():
        try:
            new_ports = {int(p.strip()) for p in ports_str.get().split(',') if p.strip()}
            controller.INSECURE_PORTS = new_ports
            messagebox.showinfo("Guardado", "La lista de puertos inseguros ha sido actualizada.", parent=settings_window)
            # Re-aplica el filtro para actualizar colores
            if hasattr(controller, 'traffic_tab_handler'):
                controller.traffic_tab_handler.apply_filter()
            settings_window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Por favor, introduce solo números separados por comas.", parent=settings_window)

    tk.Button(settings_window, text="Guardar", command=save_settings, bg="#27ae60", fg="white", relief="flat").pack(pady=10)