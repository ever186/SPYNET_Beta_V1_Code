# ==============================================================================
# ui/main_window.py
# Ventana principal que integra todo
# ==============================================================================

import tkinter as tk
from tkinter import ttk, messagebox
import os

# Imports de los componentes de UI
from ui.dialogs import Tooltip, show_about_info, configure_virustotal_api, open_settings_window
from ui.traffic_tab import TrafficTab
from ui.devices_tab import DevicesTab
from ui.visualization_tab import VisualizationTab
from ui.network_graph_tab import NetworkGraphTab
from ui.AI_tab import AITab
# Imports de Config
from config import ICON_PATH, WINDOW_BG_COLOR, SECONDARY_BG_COLOR, TEXT_COLOR

def setup_menubar(controller):
    """
    Configura la barra de menú de la aplicación.
    (Sin cambios, ya depende del controller)
    """
    menubar = tk.Menu(controller.window)
    controller.window.config(menu=menubar)

    # --- Menú Archivo ---
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Archivo", menu=file_menu)
    file_menu.add_command(label="Guardar Sesión de Captura...", command=controller.save_session)
    file_menu.add_command(label="Cargar Sesión de Captura...", command=controller.load_session)
    file_menu.add_separator()
    file_menu.add_command(label="Exportar Vista Actual a CSV...", command=controller.export_table_to_csv)
    file_menu.add_separator()
    file_menu.add_checkbutton(label="Activar Captura en .pcap", onvalue=True, offvalue=False, 
                              variable=controller.pcap_capture_var, command=controller.toggle_pcap_capture)
    file_menu.add_command(label="Importar Archivo .pcap...", command=controller.import_pcap)
    file_menu.add_separator()
    file_menu.add_command(label="Salir", command=controller.close_application)

    # --- Menú Opciones ---
    options_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Opciones", menu=options_menu)
    options_menu.add_command(label="Configurar Puertos Inseguros...", command=lambda: open_settings_window(controller))
    options_menu.add_command(label="Configurar API de VirusTotal...", command=lambda: configure_virustotal_api(controller))

    # --- Menú Ver ---
    view_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Ver", menu=view_menu)
    view_menu.add_command(label="Capturar Dashboard como PNG", command=controller.capture_dashboard)
    view_menu.add_separator()
    
    view_menu.add_command(label="Cambiar grafico: Protocolos", command=lambda: controller.viz_tab_handler.toggle_proto_graph())
    view_menu.add_command(label="Cambiar grafico: Paises", command=lambda: controller.viz_tab_handler.toggle_country_graph())
    view_menu.add_command(label="Cambiar grafico: Puertos Inseguros", command=lambda: controller.viz_tab_handler.toggle_ports_graph())

    # --- Menú Ayuda ---
    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Ayuda", menu=help_menu)
    help_menu.add_command(label="Sobre SPYNET...", command=show_about_info)

def setup_interface(controller):
    """
    Configura la interfaz principal, botones y pestañas.
    (Actualizado para usar colores de config.py)
    """
    ImageTk = controller.ImageTk
    Image = controller.Image

    main_container = tk.Frame(controller.window, bg=WINDOW_BG_COLOR)
    main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    control_panel = tk.Frame(main_container, bg=WINDOW_BG_COLOR)
    control_panel.pack(fill=tk.X, side=tk.TOP, pady=(0, 10))

    try:
        controller.icons = {
            "start": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'start.png')).resize((24, 24))),
            "stop": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'stop.png')).resize((24, 24))),
            "pause": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'pause.png')).resize((24, 24))),
            "clear": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'clear.png')).resize((24, 24))),
            "Exportar resultado AI": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'IA_report.png')).resize((24, 24))),
            "scan": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'scan.png')).resize((24, 24))),
            "export": ImageTk.PhotoImage(Image.open(os.path.join(ICON_PATH, 'export.png')).resize((24, 24)))
        }
    except Exception as e:
        messagebox.showerror("Error de Iconos", f"No se pudieron cargar los iconos desde '{ICON_PATH}'.\nError: {e}")
        controller.icons = {}

    # --- Botones de Control (usando colores de config) ---
    btn_bg = WINDOW_BG_COLOR
    controller.start_button = tk.Button(control_panel, image=controller.icons.get("start"), command=controller.start_monitoring, bg=btn_bg, relief=tk.FLAT, borderwidth=0)
    controller.start_button.pack(side=tk.LEFT, padx=5)
    Tooltip(controller.start_button, "Iniciar Captura")

    controller.stop_button = tk.Button(control_panel, image=controller.icons.get("stop"), command=controller.stop_monitoring, bg=btn_bg, relief=tk.FLAT, borderwidth=0, state=tk.DISABLED)
    controller.stop_button.pack(side=tk.LEFT, padx=5)
    Tooltip(controller.stop_button, "Detener Captura")

    controller.pause_button = tk.Button(control_panel, image=controller.icons.get("pause"), command=controller.toggle_pause, bg=btn_bg, relief=tk.FLAT, borderwidth=0, state=tk.DISABLED)
    controller.pause_button.pack(side=tk.LEFT, padx=5)
    Tooltip(controller.pause_button, "Pausar/Reanudar Captura")

    controller.clear_button = tk.Button(control_panel, image=controller.icons.get("clear"), command=controller.clear_data, bg=btn_bg, relief=tk.FLAT, borderwidth=0)
    controller.clear_button.pack(side=tk.LEFT, padx=5)
    Tooltip(controller.clear_button, "Limpiar Tabla y Gráfico")

    controller.export_ai_button = tk.Button(control_panel, image=controller.icons.get("Exportar resultado AI"), bg=btn_bg, relief=tk.FLAT, borderwidth=0)
    controller.export_ai_button.pack(side=tk.LEFT, padx=(5))
    Tooltip(controller.export_ai_button, "Exportar Reporte de IA a CSV")

    controller.export_button = tk.Button(control_panel, image=controller.icons.get("export"), command=controller.export_table_to_csv, bg=btn_bg, relief=tk.FLAT, borderwidth=0)
    controller.export_button.pack(side=tk.LEFT, padx=5)
    Tooltip(controller.export_button, "Exportar Vista a CSV")

    controller.scan_button = tk.Button(control_panel, image=controller.icons.get("scan"), bg=btn_bg, relief=tk.FLAT, borderwidth=0)
    controller.scan_button.pack(side=tk.LEFT, padx=(5))
    Tooltip(controller.scan_button, "Buscar Dispositivos en la Red")

    controller.status_info = tk.Label(control_panel, text="Estado: Detenido | Conexiones: 0", font=("Segoe UI", 10), bg=WINDOW_BG_COLOR, fg=TEXT_COLOR)
    controller.status_info.pack(side=tk.RIGHT, padx=10)

    # --- Barra de Filtro (usando colores de config) ---
    filter_frame = tk.Frame(main_container, bg=SECONDARY_BG_COLOR)
    filter_frame.pack(fill=tk.X, pady=(5, 10))
    tk.Label(filter_frame, text="🔍 Filtro:", font=("Segoe UI", 10, "bold"), fg=TEXT_COLOR, bg=SECONDARY_BG_COLOR).pack(side=tk.LEFT, padx=(10, 5))
    filter_entry = tk.Entry(filter_frame, textvariable=controller.filter_var, bg=WINDOW_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT, font=("Segoe UI", 10), width=100)
    filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

    # --- Pestañas (Notebook) ---
    notebook = ttk.Notebook(main_container)
    notebook.pack(fill=tk.BOTH, expand=True)

    # --- Integración de Pestañas ---
    controller.traffic_tab_handler = TrafficTab(controller, notebook)
    controller.devices_tab_handler = DevicesTab(controller, notebook)
    controller.viz_tab_handler = VisualizationTab(controller, notebook)
    controller.net_graph_tab_handler = NetworkGraphTab(controller, notebook)
    controller.AI_tab_handler = AITab(controller, notebook)

    controller.export_ai_button.config(command=controller.AI_tab_handler.export_to_csv)
    controller.filter_var.trace("w", controller.traffic_tab_handler.apply_filter)
    controller.scan_button.config(command=controller.devices_tab_handler.scan_network)