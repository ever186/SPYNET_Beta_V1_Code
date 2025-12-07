# ==============================================================================
# ui/AI_tab.py
# Pestaña dedicada para la IA de Deep Learning
# ==============================================================================

import tkinter as tk
from tkinter import ttk

class AITab:
    def __init__(self, controller, notebook):
        self.controller = controller
        self.frame = tk.Frame(notebook, bg='#1e272e') # Fondo oscuro
        notebook.add(self.frame, text="Modelo AI")
        
        # --- SECCIÓN 1: LOS 3 NÚMEROS PRINCIPALES ---
        stats_frame = tk.Frame(self.frame, bg='#1e272e')
        stats_frame.pack(fill=tk.X, padx=10, pady=15)
        
        # Estilo de las tarjetas de números
        def create_stat_card(parent, title, color):
            frame = tk.Frame(parent, bg=color, padx=2, pady=2)
            frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            inner = tk.Frame(frame, bg='#2f3640')
            inner.pack(fill=tk.BOTH, expand=True)
            
            lbl_title = tk.Label(inner, text=title, bg='#2f3640', fg='white', font=("Segoe UI", 10))
            lbl_title.pack(pady=(5,0))
            
            lbl_value = tk.Label(inner, text="0", bg='#2f3640', fg=color, font=("Consolas", 24, "bold"))
            lbl_value.pack(pady=(0,5))
            return lbl_value

        self.lbl_scanned = create_stat_card(stats_frame, "PAQUETES ANALIZADOS", "#3498db") # Azul
        self.lbl_suspicious = create_stat_card(stats_frame, "SOSPECHOSOS (Warning)", "#f1c40f") # Amarillo
        self.lbl_critical = create_stat_card(stats_frame, "CRÍTICOS (Ataques)", "#e74c3c") # Rojo

        # --- SECCIÓN 2: TABLA DE ALERTAS ---
        table_frame = tk.Frame(self.frame, bg='#1e272e')
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(table_frame, text="Bitácora de Detección en Tiempo Real", bg='#1e272e', fg='white', font=("Segoe UI", 10, "bold")).pack(anchor="w")

        cols = ("Hora", "Tipo de Ataque", "IP Origen", "IP Destino", "Confianza")
        self.ai_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=15)
        
        self.ai_tree.heading("Hora", text="Hora")
        self.ai_tree.heading("Tipo de Ataque", text="Clasificación IA")
        self.ai_tree.heading("IP Origen", text="IP Origen")
        self.ai_tree.heading("IP Destino", text="IP Destino")
        self.ai_tree.heading("Confianza", text="Confianza %")
        
        self.ai_tree.column("Hora", width=80, anchor="center")
        self.ai_tree.column("Tipo de Ataque", width=150, anchor="center")
        self.ai_tree.column("IP Origen", width=120, anchor="center")
        self.ai_tree.column("IP Destino", width=120, anchor="center")
        self.ai_tree.column("Confianza", width=80, anchor="center")

        # COLORES DE FILAS
        self.ai_tree.tag_configure('suspicious', background='#f39c12', foreground='black') # Amarillo
        self.ai_tree.tag_configure('critical', background='#c0392b', foreground='white')   # Rojo
        self.ai_tree.tag_configure('normal', background='white', foreground='black')       # Blanco (opcional)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.ai_tree.yview)
        self.ai_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ai_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Contadores internos
        self.count_scanned = 0
        self.count_suspicious = 0
        self.count_critical = 0

    def add_alert(self, timestamp, attack_type, src, dst, confidence, severity):
        """
        Agrega una alerta a la tabla y actualiza los contadores.
        severity: 'suspicious' o 'critical'
        """
        self.count_scanned += 1
        
        if severity == 'suspicious':
            self.count_suspicious += 1
            self.ai_tree.insert('', 0, values=(timestamp, attack_type, src, dst, confidence), tags=('suspicious',))
        elif severity == 'critical':
            self.count_critical += 1
            self.ai_tree.insert('', 0, values=(timestamp, attack_type, src, dst, confidence), tags=('critical',))
        
        # Actualizar etiquetas
        self.lbl_scanned.config(text=str(self.count_scanned))
        self.lbl_suspicious.config(text=str(self.count_suspicious))
        self.lbl_critical.config(text=str(self.count_critical))

    def update_scan_count(self):
        """Solo actualiza el contador de analizados (para tráfico normal)"""
        self.count_scanned += 1
        if self.count_scanned % 1 == 0:
            self.lbl_scanned.config(text=str(self.count_scanned))

    def clear(self):
        self.count_scanned = 0
        self.count_suspicious = 0
        self.count_critical = 0
        self.lbl_scanned.config(text="0")
        self.lbl_suspicious.config(text="0")
        self.lbl_critical.config(text="0")
        for item in self.ai_tree.get_children():
            self.ai_tree.delete(item)
    
    def export_to_csv(self):
    
        from utils.ai_export import export_ai_results_to_csv
        
        stats = {
            'scanned': self.count_scanned,
            'suspicious': self.count_suspicious,
            'critical': self.count_critical
        }
        
        export_ai_results_to_csv(self.ai_tree, stats, self.controller.window)