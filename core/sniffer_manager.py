# ==============================================================================
# core/sniffer_manager.py
# GESTOR DE CAPTURA ROBUSTO (CORREGIDO)
# ==============================================================================

import threading
import time
import logging
from queue import Queue, Empty, Full
from scapy.all import get_if_list, Ether, sniff, get_if_hwaddr

class SnifferWorker(threading.Thread):
    def __init__(self, iface, packet_queue, stop_event, use_pcap=True, status_callback=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.queue = packet_queue
        self.stop_event = stop_event
        self.use_pcap = use_pcap
        self.status_callback = status_callback
        self._packet_count = 0
        self.name = f"Worker-{iface}"

    def _log(self, message, level="INFO"):
        if self.status_callback: self.status_callback(f"[{self.iface}] {message}", level)

    def run(self):
        self._log("Iniciando motor de captura ultra-sensible...")
        try:
            # Intentar captura de bajo nivel (pcap) para no perder paquetes
            if self.use_pcap:
                self._capture_native()
            else:
                self._capture_scapy()
        except Exception as e:
            self._log(f"Error: {e}", "ERROR")
            self._capture_scapy() # Fallback final

    def _capture_native(self):
        """Captura optimizada usando LibPcap si está disponible."""
        try:
            import pcap
            pc = pcap.pcap(name=self.iface, promisc=True, immediate=True, snaplen=65535)
            for ts, raw_pkt in pc:
                if self.stop_event.is_set(): break
                self._process_raw(raw_pkt)
        except:
            self._capture_scapy()

    def _capture_scapy(self):
        """Bucle infinito de Scapy con manejo de errores."""
        while not self.stop_event.is_set():
            try:
                # Sniffing sin almacenamiento en memoria (store=0) es vital
                sniff(
                    iface=self.iface,
                    prn=self._process_raw,
                    store=0,
                    timeout=2,
                    filter="" # Capturar TODO
                )
            except:
                time.sleep(1)

    def _process_raw(self, raw_pkt):
        """Convierte y encola con prioridad de velocidad."""
        try:
            # Si ya viene como objeto Scapy (desde sniff)
            if not isinstance(raw_pkt, bytes):
                pkt = raw_pkt
            else:
                pkt = Ether(raw_pkt)
            
            self._packet_count += 1
            # put_nowait para no bloquear el hilo de captura; si la cola está llena, el paquete se descarta
            # para salvar la estabilidad del sistema.
            self.queue.put_nowait(pkt)
        except Full:
            pass # Sobrecarga: preferimos perder un frame que congelar la red
        except:
            pass

class SnifferManager:
    def __init__(self, packet_callback, status_callback=None, use_pcap=True):
        self.packet_callback = packet_callback
        self.status_callback = status_callback
        self.stop_event = threading.Event()
        # Aumentamos el tamaño de la cola a 20,000 para ráfagas de tráfico
        self.packet_queue = Queue(maxsize=20000)
        self.workers = {}
        self.dispatcher_thread = None
        self._is_active = False

    def _get_interfaces(self):
        """Detección inteligente de interfaces activas."""
        try:
            ifaces = get_if_list()
            valid = []
            for i in ifaces:
                try:
                    get_if_hwaddr(i)
                    valid.append(i)
                except: continue
            return valid
        except: return []

    def start(self):
        if self._is_active: return
        self.stop_event.clear()
        
        # Limpiar cola
        while not self.packet_queue.empty():
            try: self.packet_queue.get_nowait()
            except Empty: break

        interfaces = self._get_interfaces()
        for iface in interfaces:
            worker = SnifferWorker(iface, self.packet_queue, self.stop_event, status_callback=self.status_callback)
            self.workers[iface] = worker
            worker.start()

        self.dispatcher_thread = threading.Thread(target=self._dispatcher_loop, daemon=True)
        self.dispatcher_thread.start()
        self._is_active = True

    def _dispatcher_loop(self):
        """Repartidor de paquetes optimizado."""
        while not self.stop_event.is_set():
            try:
                # Sacamos paquetes en bloque si es necesario para reducir overhead
                pkt = self.packet_queue.get(timeout=0.1)
                self.packet_callback(pkt)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception:
                continue

    def stop(self):
        self.stop_event.set()
        self._is_active = False
