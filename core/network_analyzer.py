# ==============================================================================
# core/network_analyzer.py
# Controlador principal con HILO SEPARADO PARA IA
# ==============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, filedialog
import os
import sys
import threading
from datetime import datetime
import ipaddress
import queue

# Imports de módulos del proyecto
from utils.network_utils import resolve_ip, get_network_range, bloquear_ip, desbloquear_ip
from utils.file_operations import save_session_data, load_session_data, export_csv_data
from utils.geoip_handler import GeoIPHandler
from core.anomaly_detector import AIAnomalyDetector
from core.packet_handler import PacketHandler
from ui.main_window import setup_menubar, setup_interface

from core.sniffer_manager import SnifferManager

try:
    from config import *
except ImportError:
    print("ERROR: No se pudo encontrar config.py.")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp, rdpcap
    from scapy.utils import PcapWriter, PcapReader
    from PIL import Image, ImageTk, ImageGrab
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib.dates as mdates
    import requests
    import networkx as nx
except ImportError as e:
    messagebox.showerror("Error de Dependencia", f"Falta un paquete: {e}")
    sys.exit(1)


class NetworkAnalyzer:
    """
    Clase principal que actúa como controlador de la aplicación.
    CON HILO SEPARADO PARA ANÁLISIS DE IA.
    """
    
    def __init__(self):
        self.SCRIPT_DIR = SCRIPT_DIR 
        
        # Asignaciones de módulos dinámicos
        self.scapy_sniff, self.scapy_IP, self.scapy_TCP, self.scapy_UDP, self.scapy_ICMP = sniff, IP, TCP, UDP, ICMP
        self.scapy_ARP, self.scapy_Ether, self.scapy_srp = ARP, Ether, srp
        self.PcapWriter = PcapWriter
        self.Image, self.ImageTk = Image, ImageTk
        self.Figure, self.FigureCanvasTkAgg, self.mdates = Figure, FigureCanvasTkAgg, mdates
        self.requests = requests
        self.nx = nx

        self.packet_buffer = []
        self.BATCH_SIZE = 100
        self.connection_count = 0

        # COLA PARA ANÁLISIS DE IA (Thread-safe) usar 1000 solo pruebas
        # self.ai_queue = queue.Queue(maxsize=1000)
        self.ai_queue = queue.Queue(maxsize=5000)
        self.ai_thread = None
        self.ai_stop_event = threading.Event()

        # Configuración de la Ventana
        self.window = tk.Tk()
        self.window.title(WINDOW_TITLE)
        self.window.geometry(WINDOW_GEOMETRY)
        self.window.configure(bg=WINDOW_BG_COLOR)
        #self.window.iconbitmap("assets/img/telarana.ico")
        if sys.platform.startswith("win"):
            self.window.iconbitmap(os.path.join(self.SCRIPT_DIR, "assets", "img", "telarana.ico"))
        else:
            icon = tk.PhotoImage(file=os.path.join(self.SCRIPT_DIR, "assets", "img", "telarana.png"))
            self.window.iconphoto(True, icon)
            
        self.monitoring_active = False
        self.is_paused = False
        self.connection_count = 0
        self.all_packets_data = []
        self.filter_var = tk.StringVar()
        self.traffic_thread = None
        self.stop_sniff_event = threading.Event()
        self.datetime = datetime 
        
        self.graph_type_proto = "barras"
        self.graph_type_country = "pastel"
        self.graph_type_ports = "barras"
        
        self.pcap_capture_active = False
        self.pcap_capture_var = tk.BooleanVar(value=False)
        self.pcap_writer = None
        
        self.virustotal_api_key = VIRUSTOTAL_API_KEY_DEFAULT
        self.INSECURE_PORTS = INSECURE_PORTS_DEFAULT
        self.SOCIAL_DOMAINS = SOCIAL_DOMAINS
        self.ADULT_DOMAINS = ADULT_DOMAINS

        self.plot_timestamps, self.plot_data, self.graph_update_job = [], [], None

        # Inicializar Componentes
        self.geoip = GeoIPHandler(GEOIP_DB_PATH)
        self.anomaly_detector = AIAnomalyDetector(model_path=IA_MODEL_PATH, scaler_path=IA_SCALER_PATH)
        self.packet_handler = PacketHandler(self)

        self.sniffer_manager = SnifferManager(
            packet_callback=self._packet_callback_bridge,
            status_callback=self._sniffer_status_callback,
            use_pcap=True
        )

        # Inicializar UI
        self.traffic_tree = None
        self.devices_tree = None
        self.traffic_tab_handler = None
        self.devices_tab_handler = None
        self.viz_tab_handler = None
        self.net_graph_tab_handler = None
        self.AI_tab_handler = None  #  IMPORTANTE
        
        setup_menubar(self)
        setup_interface(self)

        #  INICIAR HILO DE IA EN SEGUNDO PLANO
        self.start_ai_thread()

        # Soporte para línea de comandos
        if len(sys.argv) > 1:
            pcap_arg = sys.argv[1]
            if os.path.exists(pcap_arg) and pcap_arg.endswith('.pcap'):
                print(f"[CLI] Detectado archivo PCAP: {pcap_arg}")
                self.window.after(1000, lambda: self.import_pcap(pcap_arg))


    # ==========================================================================
    # BRIDGES PARA EL SNIFFER (NUEVO)
    # ==========================================================================

    def _packet_callback_bridge(self, pkt):
        """Recibe paquetes del SnifferManager y los pasa al procesador."""
        # Se llama desde el hilo del dispatcher del sniffer
        if self.monitoring_active and not self.is_paused:
            self._handle_packet(pkt, from_import=False)

    def _sniffer_status_callback(self, msg, level="INFO"):
        """Recibe logs del SnifferManager y actualiza la UI o imprime."""
        print(f"[{level}] {msg}")
        # Opcional: Mostrar errores críticos en messagebox
        if level == "ERROR" and "permisos" in msg.lower():
            self.window.after(0, lambda: messagebox.showerror("Error de Permisos", msg))
            self.stop_monitoring()

    # ==========================================================================
    #  NUEVO: HILO SEPARADO PARA ANÁLISIS DE IA
    # ==========================================================================

    def start_ai_thread(self):
        """Inicia el hilo de análisis de IA en segundo plano."""
        if self.anomaly_detector.model is None:
            print("[IA] Modelo no disponible. El análisis de IA está desactivado.")
            return
        
        self.ai_stop_event.clear()
        self.ai_thread = threading.Thread(target=self.ai_analysis_worker, daemon=True)
        self.ai_thread.start()
        print("[IA] Hilo de análisis iniciado en segundo plano.")

    def ai_analysis_worker(self):
        """
        Worker que procesa paquetes de la cola para análisis de IA.
        AHORA CUENTA TODOS LOS PAQUETES (incluidos normales).
        """
        while not self.ai_stop_event.is_set():
            try:
                # Timeout para verificar periódicamente el stop_event
                packet = self.ai_queue.get(timeout=1)
                
                # Analizar el paquete con IA
                anomaly = self.anomaly_detector.analyze_packet_struct(packet)
                
                if anomaly:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    attack_type = anomaly['label']
                    src = anomaly['src']
                    dst = anomaly['dst']
                    confidence = f"{anomaly['conf'] * 100:.1f}%"
                    severity = anomaly['severity']
                    skip_alert = anomaly.get('skip_alert', False)
                    
                    # NUEVO: Actualizar GUI según el tipo
                    if skip_alert:
                        # Es tráfico normal, solo incrementar contador
                        self.window.after(0, lambda: self.AI_tab_handler.update_scan_count())
                    else:
                        # Es amenaza, agregar a tabla Y contar
                        self.window.after(0, lambda: self.AI_tab_handler.add_alert(
                            timestamp, attack_type, src, dst, confidence, severity
                        ))
                
                self.ai_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[IA ERROR] {e}")

    def stop_ai_thread(self):
        """Detiene el hilo de análisis de IA."""
        if self.ai_thread and self.ai_thread.is_alive():
            self.ai_stop_event.set()
            self.ai_thread.join(timeout=2)
            print("[IA] Hilo de análisis detenido.")

    # ==========================================================================
    # LÓGICA DE CAPTURA (SIN CAMBIOS, pero encolando paquetes para IA)
    # ==========================================================================

    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.is_paused = False
            #self.stop_sniff_event.clear()
            self.start_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.NORMAL)
            #self.update_status("Capturando", self.connection_count)
            #self.traffic_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
            #self.traffic_thread.start()
            #self.viz_tab_handler.update_graph()

            try:
                self.sniffer_manager.start()
                self.update_status("Capturando", self.connection_count)
                if self.viz_tab_handler: self.viz_tab_handler.update_graph()
            except Exception as e:
                self.monitoring_active = False
                messagebox.showerror("Error al iniciar", str(e))
                self.stop_monitoring()

    def stop_monitoring(self):
        if self.monitoring_active:
            self.monitoring_active = False
            #self.stop_sniff_event.set()
            self.sniffer_manager.stop()
            self.start_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.DISABLED)
            self.update_status("Detenido", self.connection_count)
            if self.graph_update_job: 
                self.window.after_cancel(self.graph_update_job)
                self.graph_update_job = None

    def toggle_pause(self):
        if self.monitoring_active:
            self.is_paused = not self.is_paused
            status = "Pausado" if self.is_paused else "Capturando"
            self.update_status(status, self.connection_count)

    def analyze_traffic(self):
        try: 
           self.scapy_sniff(prn=self._handle_packet, 
                            store=0, 
                            stop_filter=lambda x: self.stop_sniff_event.is_set())
        except Exception as e:
            msg = "Se requieren privilegios de administrador." if "permitted" in str(e) else f"Error: {e}"
            self.window.after(0, lambda: messagebox.showerror("Error de Captura", msg))
            self.window.after(0, self.stop_monitoring)

    def _handle_packet(self, packet, from_import=False):
        if not from_import and (not self.monitoring_active or self.is_paused): 
            return

        # Solo guardar en PCAP si es tráfico en vivo
        if not from_import and self.pcap_capture_active and self.pcap_writer:
            self.pcap_writer.write(packet)

        packet_data = self.packet_handler.process_packet(packet)

        if packet_data:
            self.connection_count += 1
            self.all_packets_data.append(packet_data)
            
            # ENCOLAR PAQUETE PARA ANÁLISIS DE IA (sin bloquear)
            if not from_import and self.ai_thread and self.ai_thread.is_alive():
                try:
                    self.ai_queue.put_nowait(packet_data['packet'])
                except queue.Full:
                    pass  # La cola está llena, descartamos este paquete

            table_row = packet_data['values']
            tags = packet_data['tags']

            # Actualizar GUI
            filter_text = self.filter_var.get().lower()
            if not filter_text or filter_text in ' '.join(map(str, table_row)).lower():
                self.window.after(0, lambda r=table_row, t=tags: self.traffic_tree.insert('', 'end', values=r, tags=t))

            self.window.after(0, lambda c=self.connection_count: self.update_status("Capturando", c))
            self.plot_timestamps.append(packet_data['timestamp'])
            self.plot_data.append(packet_data['size'] / 1024) 
            
            # Actualizar gráficos periódicamente
            if self.connection_count % 10 == 0:
                self.window.after(0, self.viz_tab_handler.update_statistics)

    # ==========================================================================
    # IMPORTACIÓN PCAP (CON ANÁLISIS DE IA OPCIONAL)
    # ==========================================================================

    def import_pcap(self, filepath=None):
        """Carga un archivo .pcap y procesa los paquetes."""
        
        if not filepath:
            filepath = filedialog.askopenfilename(
                title="Importar Archivo PCAP",
                filetypes=[("Archivos PCAP", "*.pcap"), ("Todos los archivos", "*.*")]
            )
        if not filepath: return

        fast_mode = messagebox.askyesno("Modo de Importación", 
            "¿Quieres usar el MODO RÁPIDO (Solo Vista)?\n\n"
            "SÍ: Carga instantánea, sin IA, sin resolución DNS lenta.\n"
            "NO: Análisis completo (IA, DNS), más lento.")

        self.clear_data()
        self.update_status("Iniciando lectura de flujo...", 0)
        
        def load_worker():
            try:
                count = 0
                batch_rows = []
                
                print(f"[PCAP] Abriendo flujo: {filepath}")
                
                with PcapReader(filepath) as pcap_reader:
                    for pkt in pcap_reader:
                        packet_data = self.packet_handler.process_packet(pkt, fast_mode=fast_mode)
                        
                        if packet_data:
                            self.all_packets_data.append(packet_data)
                            batch_rows.append(packet_data)
                            count += 1
                            
                            # ANÁLISIS DE IA PARA ARCHIVOS PCAP (si no es fast_mode)
                            if not fast_mode and self.ai_thread and self.ai_thread.is_alive():
                                try:
                                    self.ai_queue.put_nowait(pkt)
                                except queue.Full:
                                    pass
                        
                        # Actualización por lotes
                        if len(batch_rows) >= 500:
                            self._batch_insert(batch_rows)
                            batch_rows = []
                            self.window.after(0, lambda c=count: self.update_status(f"Cargados: {c}", c))
                
                if batch_rows:
                    self._batch_insert(batch_rows)
                
                self.window.after(0, self.viz_tab_handler.update_statistics)
                self.window.after(0, lambda: messagebox.showinfo("Importación Finalizada", f"Total: {count}"))
                self.window.after(0, lambda: self.update_status("Archivo Cargado", count))

            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("Error", f"Fallo:\n{e}"))

        threading.Thread(target=load_worker, daemon=True).start()

    def _batch_insert(self, packet_list):
        """Inserta múltiples filas en la tabla de una sola vez."""
        def _gui_update():
            for p in packet_list:
                self.traffic_tree.insert('', 'end', values=p['values'], tags=p['tags'])
            if packet_list:
                self.traffic_tree.see(self.traffic_tree.get_children()[-1])
                
        self.window.after(0, _gui_update)

    # ==========================================================================
    # RESTO DE MÉTODOS (SIN CAMBIOS)
    # ==========================================================================

    def clear_data(self):
        self.filter_var.set("")
        if self.traffic_tree:
            for i in self.traffic_tree.get_children(): 
                self.traffic_tree.delete(i)
        
        self.all_packets_data.clear()
        self.connection_count = 0
        self.update_status("Detenido", 0)
        self.plot_timestamps.clear()
        self.plot_data.clear()
        
        if self.viz_tab_handler:
            self.viz_tab_handler.ax.clear()
            self.viz_tab_handler.canvas.draw()
            self.viz_tab_handler.update_statistics()
        
        if self.net_graph_tab_handler and self.net_graph_tab_handler.ax_net:
            self.net_graph_tab_handler.ax_net.clear()
            self.net_graph_tab_handler.canvas_net.draw()
        
        # Limpiar pestaña de IA
        if self.AI_tab_handler:
            self.AI_tab_handler.clear()

    def update_status(self, status, count):
        self.status_info.config(text=f"Estado: {status} | Conexiones: {count}")

    def save_session(self):
        save_session_data(self.all_packets_data, self.window)

    def load_session(self):
        loaded_data = load_session_data(self.window)
        if loaded_data:
            self.clear_data()
            self.all_packets_data = loaded_data
            self.traffic_tab_handler.apply_filter()
            self.connection_count = len(self.all_packets_data)
            self.update_status("Sesión Cargada", self.connection_count)

    def export_table_to_csv(self):
        export_csv_data(self.traffic_tree, self.window)

    def open_csv(self):
        messagebox.showinfo("Información", "Usa 'Exportar a CSV' para guardar la vista actual.")

    def get_network_range(self):
        return get_network_range() 

    def resolve_ip(self, ip):
        return resolve_ip(ip)

    def query_virustotal(self, resource_to_check):
        if not self.virustotal_api_key:
            messagebox.showwarning("API Key Faltante", "Configura tu API Key en Opciones.")
            return

        wait_window = Toplevel(self.window); wait_window.title("Consultando...")
        wait_window.geometry("300x100")
        tk.Label(wait_window, text=f"Consultando VirusTotal para:\n{resource_to_check}", pady=20).pack()
        wait_window.update()

        def do_query():
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource_to_check}"
            headers = {"x-apikey": self.virustotal_api_key}
            try:
                response = self.requests.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                result_str = (f"Resultados para: {resource_to_check}\n\n"
                              f"Inofensivo: {stats.get('harmless', 0)}\n"
                              f"Malicioso: {stats.get('malicious', 0)}\n"
                              f"Sospechoso: {stats.get('suspicious', 0)}\n")
                wait_window.destroy()
                messagebox.showinfo("Resultado VT", result_str)
            except Exception as e:
                wait_window.destroy()
                messagebox.showerror("Error de API", f"{e}")
        
        threading.Thread(target=do_query, daemon=True).start()

    def analyze_selected_ip_vt(self):
        selected_item = self.traffic_tree.focus()
        if not selected_item: return
        ip_origen = self.traffic_tree.item(selected_item)['values'][2]
        self.query_virustotal(ip_origen)

    def analyze_selected_domain_vt(self):
        selected_item = self.traffic_tree.focus()
        if not selected_item: return
        domain = self.traffic_tree.item(selected_item)['values'][4]
        self.query_virustotal(domain)
    
    def capture_dashboard(self):
        try:
            viz_frame = self.viz_tab_handler.frame
            x = viz_frame.winfo_rootx(); y = viz_frame.winfo_rooty()
            w = viz_frame.winfo_width(); h = viz_frame.winfo_height()
            
            snapshot = ImageGrab.grab(bbox=(x, y, x + w, y + h))
            filename = self.datetime.now().strftime(DASHBOARD_SNAPSHOT_FORMAT)
            snapshot.save(filename)
            messagebox.showinfo("Captura Exitosa", f"Dashboard guardado como {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo capturar: {e}")

    def toggle_pcap_capture(self):
        is_checked = self.pcap_capture_var.get()
        if is_checked and not self.pcap_capture_active:
            try:
                filename = self.datetime.now().strftime(PCAP_FILENAME_FORMAT)
                self.pcap_writer = self.PcapWriter(filename, append=True, sync=True)
                self.pcap_capture_active = True
                messagebox.showinfo("PCAP Activado", f"Guardando en:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error PCAP", f"{e}")
                self.pcap_capture_var.set(False)
        elif not is_checked and self.pcap_capture_active:
            if self.pcap_writer:
                self.pcap_writer.close()
                messagebox.showinfo("PCAP Detenido", "Captura guardada.")
            self.pcap_writer = None
            self.pcap_capture_active = False

    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.close_application)
        self.window.mainloop()

    def close_application(self):
        # Detener hilo de IA antes de cerrar
        self.stop_ai_thread()
        
        if self.pcap_capture_active and self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
        
        #if self.sniffer_manager:
            #self.sniffer_manager.stop()

        self.stop_monitoring()
        self.window.destroy() 

