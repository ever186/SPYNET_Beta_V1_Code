# ==============================================================================
# ui/visualization_tab.py
# Gráficos y estadísticas
# ==============================================================================

import tkinter as tk
from collections import Counter
from tkinter import messagebox

# Estos imports deben ser cargados dinámicamente por el controller
# from matplotlib.figure import Figure
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# import matplotlib.dates as mdates

class VisualizationTab:
    """
    Clase que gestiona la pestaña 'Visualización' y sus gráficos.
    """

    def __init__(self, controller, notebook):
        self.controller = controller
        self.frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.frame, text="Visualización")
        self.setup_visualization_tab(self.frame)

    def setup_visualization_tab(self, parent_frame):
        """
        Crea los 4 sub-gráficos para la visualización de datos.
        Extraído de SPYNET V3.5.1 (líneas ~390-450)
        """
        # Accede a los módulos de matplotlib cargados por el controller
        Figure = self.controller.Figure
        FigureCanvasTkAgg = self.controller.FigureCanvasTkAgg
        self.mdates = self.controller.mdates

        grid_frame = tk.Frame(parent_frame, bg="#ffffff")
        grid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        fig_size = (5.5, 3.8)

        # Gráfico: Tráfico en el tiempo
        self.fig = Figure(figsize=fig_size, dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#ecf0f1')
        self.ax.set_title("Tráfico en Tiempo Real")
        self.ax.set_xlabel("Tiempo"); self.ax.set_ylabel("KB/s")
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.canvas = FigureCanvasTkAgg(self.fig, master=grid_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Gráfico: Protocolos usados
        self.fig_proto = Figure(figsize=fig_size, dpi=100)
        self.ax_proto = self.fig_proto.add_subplot(111)
        self.ax_proto.set_title("Protocolos Detectados")
        self.canvas_proto = FigureCanvasTkAgg(self.fig_proto, master=grid_frame)
        self.canvas_proto.draw()
        self.canvas_proto.get_tk_widget().grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Gráfico: Países
        self.fig_country = Figure(figsize=fig_size, dpi=100)
        self.ax_country = self.fig_country.add_subplot(111)
        self.ax_country.set_title("Países de Origen")
        self.canvas_country = FigureCanvasTkAgg(self.fig_country, master=grid_frame)
        self.canvas_country.draw()
        self.canvas_country.get_tk_widget().grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # Gráfico: Puertos inseguros
        self.fig_ports = Figure(figsize=fig_size, dpi=100)
        self.ax_ports = self.fig_ports.add_subplot(111)
        self.ax_ports.set_title("Puertos Inseguros Detectados")
        self.canvas_ports = FigureCanvasTkAgg(self.fig_ports, master=grid_frame)
        self.canvas_ports.draw()
        self.canvas_ports.get_tk_widget().grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        grid_frame.grid_rowconfigure(0, weight=1)
        grid_frame.grid_rowconfigure(1, weight=1)
        grid_frame.grid_columnconfigure(0, weight=1)
        grid_frame.grid_columnconfigure(1, weight=1)

    def update_statistics(self):
        """
        Actualiza los gráficos de estadísticas (protocolos, países, puertos).
        Extraído de SPYNET V1.0
        """
        if not self.controller.all_packets_data:
            return

        protocols, countries, insecure_ports = [], [], []

        for data in self.controller.all_packets_data:
            values = data['values']
            protocols.append(values[5]) # Protocolo
            countries.append(values[1]) # País
            port_str = values[6] # Puerto
            if port_str != "-" and int(port_str) in self.controller.INSECURE_PORTS:
                insecure_ports.append(port_str)

        # --- Protocolos
        self.ax_proto.clear()
        proto_counts = Counter(protocols)
        if self.controller.graph_type_proto == "barras":
            self.ax_proto.bar(proto_counts.keys(), proto_counts.values(), color='#2980b9')
        else:
            self.ax_proto.pie(proto_counts.values(), labels=proto_counts.keys(), autopct="%1.1f%%")
        self.ax_proto.set_title("Protocolos")
        self.canvas_proto.draw()

        # --- Países 
        self.ax_country.clear()
        country_counts = Counter(countries)
        if self.controller.graph_type_country == "pastel":
            self.ax_country.pie(country_counts.values(), labels=country_counts.keys(), autopct="%1.1f%%", startangle=140)
        else:
            self.ax_country.bar(country_counts.keys(), country_counts.values(), color='#2ecc71')
        self.ax_country.set_title("Países")
        self.canvas_country.draw()

        # --- Puertos inseguros
        self.ax_ports.clear()
        port_counts = Counter(insecure_ports)
        if self.controller.graph_type_ports == "barras":
            self.ax_ports.bar(port_counts.keys(), port_counts.values(), color='#e74c3c')
        else:
            self.ax_ports.pie(port_counts.values(), labels=port_counts.keys(), autopct="%1.1f%%")
        self.ax_ports.set_title("Puertos inseguros")
        self.canvas_ports.draw()

    def update_graph(self):
        """
        Actualiza el gráfico de tráfico en tiempo real.
        Extraído de SPYNET V3.5.1 (líneas ~980-1020)
        """
        if not self.controller.monitoring_active: return
        self.ax.clear()
        if self.controller.plot_timestamps:
            max_points = 300
            current_time = self.controller.datetime.now()
            data_per_second = {}
            
            for i in range(len(self.controller.plot_timestamps) - 1, -1, -1):
                ts = self.controller.plot_timestamps[i]
                if (current_time - ts).total_seconds() > max_points: break
                sec_timestamp = ts.replace(microsecond=0)
                data_per_second[sec_timestamp] = data_per_second.get(sec_timestamp, 0) + self.controller.plot_data[i]
            
            if data_per_second:
                sorted_times = sorted(data_per_second.keys())
                sorted_values = [data_per_second[t] for t in sorted_times]
                self.ax.plot(sorted_times, sorted_values, color='#3498db', marker='o', linestyle='-', markersize=3)
                self.ax.fill_between(sorted_times, sorted_values, color='#3498db', alpha=0.2)
        
        self.ax.xaxis.set_major_formatter(self.mdates.DateFormatter('%H:%M:%S'))
        self.ax.tick_params(axis='x', rotation=30, labelsize=8)
        self.ax.set_xlabel("Tiempo", fontsize=10)
        self.ax.set_ylabel("Tráfico (KB/s)", fontsize=10)
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.fig.tight_layout()
        self.canvas.draw()
        
        self.controller.graph_update_job = self.controller.window.after(1000, self.update_graph)

    # --- Funciones Toggle ---
    
    def toggle_proto_graph(self):
        self.controller.graph_type_proto = "pastel" if self.controller.graph_type_proto == "barras" else "barras"
        self.update_statistics()

    def toggle_country_graph(self):
        self.controller.graph_type_country = "barras" if self.controller.graph_type_country == "pastel" else "pastel"
        self.update_statistics()

    def toggle_ports_graph(self):
        self.controller.graph_type_ports = "pastel" if self.controller.graph_type_ports == "barras" else "barras"
        self.update_statistics()


