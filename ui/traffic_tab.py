# ==============================================================================
# ui/traffic_tab.py
# Configuración de la pestaña de análisis de tráfico
# ==============================================================================

import tkinter as tk
from tkinter import ttk, Toplevel, Text
import sys
from io import StringIO
from config import TAG_INSECURE, TAG_SOCIAL, TAG_ADULT, TAG_ANOMALY

class TrafficTab:
    """
    Clase que gestiona la pestaña 'Análisis de Tráfico'.
    """
    
    def __init__(self, controller, notebook):
        self.controller = controller
        self.frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.frame, text="Análisis de Tráfico")
        self.setup_traffic_table(self.frame)

    def setup_traffic_table(self, parent_frame):
        """
        Crea la tabla (Treeview) para mostrar el tráfico de red.
        (Actualizado para usar tags de config.py)
        """
        frame = tk.Frame(parent_frame, bg='#ffffff')
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        cols = ("Tiempo", "País", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Detalles")
        self.controller.traffic_tree = ttk.Treeview(frame, columns=cols, show="headings")
        
        for col in cols: 
            self.controller.traffic_tree.heading(col, text=col)
        
        self.controller.traffic_tree.column("Tiempo", width=80, anchor='center')
        self.controller.traffic_tree.column("País", width=60, anchor='center')
        self.controller.traffic_tree.column("Origen", width=120)
        self.controller.traffic_tree.column("Destino", width=120)
        self.controller.traffic_tree.column("Dominio", width=200)
        self.controller.traffic_tree.column("Protocolo", width=80, anchor='center')
        self.controller.traffic_tree.column("Puerto", width=60, anchor='center')
        self.controller.traffic_tree.column("Tamaño", width=80, anchor='center')
        self.controller.traffic_tree.column("Detalles", width=300)
        
        # --- Tags desde config ---
        self.controller.traffic_tree.tag_configure(TAG_INSECURE, background='#e74c3c', foreground='white')
        self.controller.traffic_tree.tag_configure(TAG_SOCIAL, background='#3498db', foreground='white')
        self.controller.traffic_tree.tag_configure(TAG_ADULT, background='#9b59b6', foreground='white')
        self.controller.traffic_tree.tag_configure(TAG_ANOMALY, background="#e4e4e4", foreground='black')

        self.controller.traffic_tree.bind("<Double-1>", self.show_packet_details)

        v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.controller.traffic_tree.yview)
        self.controller.traffic_tree.configure(yscrollcommand=v_scrollbar.set)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        h_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.controller.traffic_tree.xview)
        self.controller.traffic_tree.configure(xscrollcommand=h_scrollbar.set)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.controller.traffic_tree.pack(fill=tk.BOTH, expand=True)
        
        # Menú contextual para VirusTotal
        traffic_menu = tk.Menu(self.controller.traffic_tree, tearoff=0)
        traffic_menu.add_command(label="Analizar IP Origen con VirusTotal", command=self.controller.analyze_selected_ip_vt)
        traffic_menu.add_command(label="Analizar Dominio Destino con VirusTotal", command=self.controller.analyze_selected_domain_vt)

        def show_traffic_menu(event):
            item = self.controller.traffic_tree.identify_row(event.y)
            if item:
                self.controller.traffic_tree.selection_set(item)
                traffic_menu.post(event.x_root, event.y_root)

        self.controller.traffic_tree.bind("<Button-3>", show_traffic_menu)

    def show_packet_details(self, event):
        """
        Muestra una ventana con los detalles completos del paquete.
        """
        item_id = self.controller.traffic_tree.focus()
        if not item_id: return

        item_index = self.controller.traffic_tree.index(item_id)
        
        filter_text = self.controller.filter_var.get().lower()
        if filter_text:
            visible_packets = [p for p in self.controller.all_packets_data if filter_text in ' '.join(map(str, p['values'])).lower()]
            if item_index < len(visible_packets):
                packet_obj = visible_packets[item_index]['packet']
            else: return
        else:
            if item_index >= len(self.controller.all_packets_data): return
            packet_obj = self.controller.all_packets_data[item_index]['packet']

        details_window = Toplevel(self.controller.window)
        details_window.title("Detalles del Paquete")
        details_window.geometry("800x600")
        details_window.configure(bg="#2c3e50")
        
        text_area = Text(details_window, bg="#2c3e50", fg="white", font=("Consolas", 10), wrap="word")
        text_area.pack(expand=True, fill="both", padx=10, pady=10)
        
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        packet_obj.show()
        sys.stdout = old_stdout
        
        packet_details_str = captured_output.getvalue()
        text_area.insert("1.0", packet_details_str)
        text_area.config(state="disabled")

    def apply_filter(self, *args):
        """
        Filtra la tabla de tráfico en tiempo real.
        """
        filter_text = self.controller.filter_var.get().lower()
        
        for i in self.controller.traffic_tree.get_children():
            self.controller.traffic_tree.delete(i)
        
        for packet_data in self.controller.all_packets_data:
            if filter_text in ' '.join(map(str, packet_data['values'])).lower():
                self.controller.traffic_tree.insert('', 'end', values=packet_data['values'], tags=packet_data['tags'])