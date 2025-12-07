# ==============================================================================
# utils/installer.py
# Instalador automático de dependencias (Extraído de SPYNET V2.1)
# ==============================================================================

import sys
import os
import tkinter as tk
from tkinter import ttk, font, messagebox
import threading
import subprocess
import importlib.util
from config import REQUIRED_PACKAGES # Importa la lista desde config.py

def check_admin_privileges():
    """
    Verifica si el script se ejecuta con privilegios de administrador.
    """
    try:
        is_admin = False
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = (os.geteuid() == 0)

        if not is_admin:
            messagebox.showwarning("Permisos Insuficientes",
                                 "Se recomienda ejecutar como administrador (o con 'sudo') para una captura completa.")
    except Exception as e:
        print(f"No se pudo verificar los permisos: {e}")

def check_and_install_dependencies():
    """
    Verifica las dependencias. Si faltan, muestra la ventana de instalación.
    Devuelve True si todo está listo, False si la instalación falló.
    """
    missing_packages = []
    for module_name, package_name in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(module_name) is None:
            missing_packages.append(package_name)

    if not missing_packages:
        return True # Todo está instalado

    # Si faltan paquetes, muestra la ventana de instalación
    print(f"Faltan paquetes: {missing_packages}. Iniciando instalador...")
    installation_successful = show_installer_window(missing_packages)
    
    if not installation_successful:
        return False
    
    # Segunda verificación post-instalación
    final_missing = []
    for module_name, package_name in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(module_name) is None:
            final_missing.append(package_name)

    if final_missing:
        messagebox.showerror("Error Crítico", f"No se pudieron instalar: {final_missing}. La aplicación no puede continuar.")
        return False
        
    return True # Instalación exitosa

def show_installer_window(packages_to_install):
    """
    Crea una ventana de Tkinter para mostrar el proceso de instalación.
    Devuelve True si la instalación fue exitosa, False si no.
    """
    installer_window = tk.Tk()
    installer_window.title("SPYNET Beta V1.0 - Verificador de Herramientas")
    installer_window.geometry("550x400")
    installer_window.resizable(False, False)
    installer_window.configure(bg="#2c3e50")
    
    # Flag para saber el resultado
    installation_status = {"success": False}

    title_font = font.Font(family="Segoe UI", size=16, weight="bold")
    tk.Label(installer_window, text="Instalando dependencias...", font=title_font, fg="#ecf0f1", bg="#2c3e50").pack(pady=20)

    log_frame = tk.Frame(installer_window, bg="#34495e", padx=5, pady=5)
    log_frame.pack(pady=10, padx=20, fill="both", expand=True)
    log_text = tk.Text(log_frame, bg="#34495e", fg="#bdc3c7", relief="flat", height=10, font=("Consolas", 10), bd=0)
    log_text.pack(fill="both", expand=True, padx=1, pady=1)

    progress = ttk.Progressbar(installer_window, orient="horizontal", length=510, mode="determinate")
    progress.pack(pady=(0, 20), padx=20)

    def update_log(message):
        installer_window.after(0, lambda: log_text.insert(tk.END, message + "\n"))
        installer_window.after(0, lambda: log_text.see(tk.END))

    def installation_worker():
        progress_step = 100 / len(packages_to_install)
        all_successful = True

        for i, package_name in enumerate(packages_to_install):
            update_log(f"[*] Buscando '{package_name}'... No encontrado.")
            update_log(f"    -> Intentando instalar automáticamente...")
            try:
                command = [sys.executable, "-m", "pip", "install", package_name, "--quiet", "--disable-pip-version-check"]
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', creationflags=creationflags)
                update_log(f"    -> '{package_name}' instalado correctamente.")
            except Exception as e:
                all_successful = False
                update_log(f"[ERROR] Falló la instalación de '{package_name}'.")
                update_log(f"    -> Razón: {e}. Intenta instalarlo manualmente.")
                break
            installer_window.after(0, lambda p=progress_step * (i + 1): progress.config(value=p))

        if all_successful:
            update_log("\n[+] ¡Todas las herramientas están listas!")
            update_log("    Iniciando SPYNET 3.5...")
            installation_status["success"] = True
            installer_window.after(2000, installer_window.destroy)
        else:
            update_log("\n[!] No se pudieron instalar todas las dependencias.")
            update_log("    Por favor, abre una terminal (CMD) y ejecuta 'pip install <paquete>'.")
            installation_status["success"] = False
            close_button = tk.Button(installer_window, text="Cerrar", command=installer_window.destroy, bg="#e74c3c", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), padx=10, pady=5)
            installer_window.after(0, lambda: close_button.pack(pady=10))

    installer_window.after(250, lambda: threading.Thread(target=installation_worker, daemon=True).start())
    installer_window.mainloop()
    
    return installation_status["success"]