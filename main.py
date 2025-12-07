# ==============================================================================
# main.py
# Punto de entrada principal de SPYNET V1.0
# ==============================================================================

import sys
import os
import tkinter as tk
from tkinter import messagebox
from config import ICON_PATH

# Añade la raíz del proyecto al sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from utils.installer import check_and_install_dependencies, check_admin_privileges
except ImportError as e:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Error de Estructura", f"No se pudieron encontrar los módulos de utilidad.\n{e}")
    sys.exit(1)


def main():
    """
    Punto de entrada principal de SPYNET.
    """
    print("=" * 60)
    print("SPYNET V1.0.0 - Analizador de Red Avanzado")
    print("=" * 60)
    
    # 1. Verificar privilegios
    print("\n[1/4] Verificando privilegios de administrador...")
    check_admin_privileges()
    
    # 2. Verificar e instalar dependencias
    print("[2/4] Verificando dependencias...")
    if not check_and_install_dependencies():
        print("[ERROR] No se pudieron instalar las dependencias necesarias.")
        sys.exit(1)
    
    # 3. Mostrar splash screen ANTES de crear NetworkAnalyzer
    print("[3/4] Iniciando interfaz gráfica...")
    logo_path = os.path.join(ICON_PATH, 'telarana.png')
    
    if os.path.exists(logo_path):
        try:
            from ui.splash_screen import show_simple_splash
            print("      → Mostrando splash screen...")
            show_simple_splash(logo_path, duration_seconds=2)
        except Exception as e:
            print(f"      → Splash no disponible: {e}")
    else:
        print(f"      → Logo no encontrado: {logo_path}")
    
    # 4. AHORA SÍ crear NetworkAnalyzer (que crea su propio Tk())
    print("[4/4] Cargando componentes principales...")
    try:
        from core.network_analyzer import NetworkAnalyzer
        app = NetworkAnalyzer()
        
        print("\n" + "=" * 60)
        print("✅ SPYNET iniciado correctamente")
        print("=" * 60 + "\n")
        
        # Ejecutar la aplicación
        app.run()
        
    except Exception as e:
        messagebox.showerror("Error Crítico", f"No se pudo iniciar SPYNET:\n{e}")
        print(f"\n[ERROR FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Aplicación cerrada por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)