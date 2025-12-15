# ==============================================================================
# ui/network_graph_tab.py
# Mapa de red con NetworkX
# ==============================================================================

import tkinter as tk
from tkinter import messagebox
import ipaddress

# Estos imports deben ser cargados por el controller o estar disponibles
# import networkx as nx
# from matplotlib.figure import Figure
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class NetworkGraphTab:
    """
    Clase que gestiona la pestaña 'Mapa de Red'.
    """

    def __init__(self, controller, notebook):
        self.controller = controller
        self.frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.frame, text="Mapa de Red")
        self.setup_network_graph_tab(self.frame)

    def setup_network_graph_tab(self, parent_frame):
        """
        Configura la pestaña que contendrá el gráfico de red.
        Extraído de SPYNET V3.5.1 (líneas ~1030-1050)
        """
        Figure = self.controller.Figure
        FigureCanvasTkAgg = self.controller.FigureCanvasTkAgg

        self.fig_net = Figure(figsize=(8, 6), dpi=100)
        self.ax_net = None # Se inicializará al generar el gráfico
        self.canvas_net = FigureCanvasTkAgg(self.fig_net, master=parent_frame)
        self.canvas_net.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=False)

        btn_frame = tk.Frame(parent_frame, bg="white")
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 50), padx=(10, 10), expand=False)
        
        update_btn = tk.Button(btn_frame, text="Generar/Actualizar Gráfico de Red", command=self.update_network_graph)
        update_btn.pack()

    def update_network_graph(self):
        """
        Dibuja el gráfico de red basado en los paquetes capturados.
        Extraído de SPYNET V3.5.1 (líneas ~1060-1120)
        """
        nx = self.controller.nx # Accede a networkx cargado por el controller
        
        if not self.controller.all_packets_data:
            messagebox.showinfo("Sin Datos", "No hay datos de conexión para generar un gráfico.")
            return

        if self.ax_net:
            self.ax_net.clear()
        else:
            self.ax_net = self.fig_net.add_subplot(111)

        G = nx.DiGraph()
        local_range = ipaddress.ip_network(self.controller.get_network_range(), strict=False)

        for packet_data in self.controller.all_packets_data:
            values = packet_data['values']
            ip_src, ip_dst = values[2], values[3]
            
            # Evita IPs no válidas si las hubiera
            try:
                ip_src_obj = ipaddress.ip_address(ip_src)
                ip_dst_obj = ipaddress.ip_address(ip_dst)
            except ValueError:
                continue

            for ip, ip_obj in [(ip_src, ip_src_obj), (ip_dst, ip_dst_obj)]:
                if not G.has_node(ip):
                    is_local = ip_obj in local_range
                    G.add_node(ip, color='skyblue' if is_local else 'salmon', type='local' if is_local else 'remote')

            if G.has_edge(ip_src, ip_dst):
                G[ip_src][ip_dst]['weight'] += 1
            else:
                G.add_edge(ip_src, ip_dst, weight=1)

        pos = nx.spring_layout(G, k=0.5, iterations=50)
        node_colors = [data['color'] for node, data in G.nodes(data=True)]

        nx.draw_networkx_nodes(G, pos, node_size=700, node_color=node_colors, ax=self.ax_net)
        nx.draw_networkx_labels(G, pos, font_size=8, ax=self.ax_net)
        
        edge_weights = [G[u][v]['weight'] for u, v in G.edges()]
        max_weight = max(edge_weights) if edge_weights else 1
        edge_widths = [1 + (w / max_weight) * 4 for w in edge_weights]
        
        nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.6, edge_color='gray', ax=self.ax_net)
        
        self.ax_net.set_title("Mapa de Conexiones de Red")
        self.fig_net.tight_layout()
        self.canvas_net.draw()
