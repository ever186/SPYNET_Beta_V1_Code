# ==============================================================================
# ui/splash_screen.py
# Splash screen que NO interfiere con NetworkAnalyzer
# ==============================================================================

import tkinter as tk
from PIL import Image, ImageTk
import time


BG = "#1B1E22"
TEXT_TITLE = "#D2EAFC"
TEXT_SUB = "#E9EEF2"
TEXT_CREDITS = "#A7B4C2"

def show_simple_splash(logo_path, duration_seconds=2):

    # Crear ventana temporal
    splash_root = tk.Tk()
    splash_root.overrideredirect(True)  # Sin bordes
    splash_root.configure(bg=BG)
    
    # Tamaño y posición
    width = 450
    height = 300
    x = (splash_root.winfo_screenwidth() - width) // 2
    y = (splash_root.winfo_screenheight() - height) // 2
    splash_root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Cargar logo
    try:
        img = Image.open(logo_path)
        img = img.resize((150, 150), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        label = tk.Label(splash_root, image=photo, bg=BG,)
        label.image = photo  # Mantener referencia
        label.pack(expand=True)
        text1 = tk.Label(splash_root, text="SPYNET", font=("Segoe UI", 30, "bold"), fg=TEXT_TITLE, bg=BG, padx=10)
        text1.pack()
        text2 = tk.Label(splash_root, text="Analizador de paquetes - potenciado por IA", font=("Segoe UI", 12, "bold"), fg=TEXT_SUB, bg=BG, padx=10)
        text2.pack()
        text3 = tk.Label(splash_root, text="Creado por HackCat", font=("Segoe UI", 9, "bold"), fg=TEXT_CREDITS, bg=BG, padx=10)
        text3.pack()
    except Exception as e:
        print(f"[Splash] No se pudo cargar logo: {e}")
        # Fallback: solo textoS
        tk.Label(
            splash_root,
            text="SPYNET",
            font=("Segoe UI", 20, "bold"),
            bg='#1e272e',
            fg='white'
        ).pack(expand=True)
    
    # Actualizar para que se muestre
    splash_root.update()
    
    # Esperar el tiempo especificado
    time.sleep(duration_seconds)
    
    # Destruir splash
    splash_root.destroy()
    
    print("[Splash] Splash cerrado correctamente")