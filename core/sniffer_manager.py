# ==============================================================================
# core/sniffer_manager.py
# GESTOR DE CAPTURA ROBUSTO (CORREGIDO)
# ==============================================================================

import threading
import time
import logging
from queue import Queue, Empty

# Intentar importar librerías de bajo nivel para performance
try:
    import pcap
    PCAP_AVAILABLE = True
except ImportError:
    try:
        import pcapy
        PCAP_AVAILABLE = True
    except ImportError:
        PCAP_AVAILABLE = False

from scapy.all import get_if_list, Ether, conf, sniff, get_if_hwaddr

# Configurar logging base
logging.basicConfig(level=logging.INFO, format='[SNIFFER] %(message)s')

class SnifferWorker(threading.Thread):
    """
    Worker individual asignado a una interfaz de red específica.
    """
    
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
        msg = f"[{self.iface}] {message}"
        if self.status_callback:
            self.status_callback(msg, level)
        else:
            logging.info(msg)

    def run(self):
        self._log("Iniciando captura...")
        
        try:
            # Prioridad 1: Librerías nativas (rápido)
            if self.use_pcap and PCAP_AVAILABLE:
                self._capture_native()
            else:
                # Prioridad 2: Scapy puro (lento pero compatible)
                self._capture_scapy()
        except Exception as e:
            self._log(f"Fallo crítico en worker: {e}", "ERROR")
        finally:
            self._log(f"Detenido. Paquetes capturados: {self._packet_count}")

    def _capture_native(self):
        """Intenta usar libpcap o pcapy para captura de alta velocidad."""
        try:
            import pcap
            # snaplen 65535 captura el paquete completo
            pc = pcap.pcap(name=self.iface, promisc=True, immediate=True, snaplen=65535)
            self._log("Usando driver nativo: pcap")
            
            # Bucle manual para poder salir con stop_event
            for ts, raw_pkt in pc:
                if self.stop_event.is_set(): break
                self._process_raw_packet(raw_pkt)
                
        except Exception:
            try:
                import pcapy
                # open_live(device, snaplen, promisc, timeout_ms)
                cap = pcapy.open_live(self.iface, 65535, 1, 100)
                self._log("Usando driver nativo: pcapy")
                
                while not self.stop_event.is_set():
                    try:
                        (header, packet) = cap.next()
                        if packet: self._process_raw_packet(packet)
                    except pcapy.PcapError:
                        continue # Timeout normal
            except Exception as e:
                self._log(f"Drivers nativos fallaron, cambiando a Scapy.", "WARNING")
                self._capture_scapy()

    def _capture_scapy(self):
        """Fallback a Scapy raw socket. CORREGIDO PARA BUCLE INFINITO."""
        self._log("Usando motor Scapy (Modo compatibilidad)")
        
        def _scapy_prn(pkt):
            if not self.stop_event.is_set():
                self._packet_count += 1
                try:
                    self.queue.put_nowait(pkt)
                except:
                    pass 

        # --- CORRECCIÓN CRÍTICA AQUI ---
        # Scapy sniff con timeout sale de la función. 
        # Necesitamos un bucle while para mantenerlo vivo.
        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    prn=_scapy_prn,
                    store=0,
                    promisc=True, 
                    # El stop_filter a veces no es reactivo en Windows con sockets raw
                    # por eso usamos timeout + bucle while
                    timeout=1 
                )
            except Exception as e:
                # Si falla una iteración, esperamos un poco y reintentamos
                # Esto evita que un error momentáneo mate el hilo
                if not self.stop_event.is_set():
                    time.sleep(1)

    def _process_raw_packet(self, raw_pkt):
        try:
            pkt = Ether(raw_pkt)
            self._packet_count += 1
            try:
                self.queue.put_nowait(pkt)
            except:
                pass
        except Exception:
            pass


class SnifferManager:
    def __init__(self, packet_callback, status_callback=None, use_pcap=True):
        self.packet_callback = packet_callback
        self.status_callback = status_callback
        self.use_pcap = use_pcap and PCAP_AVAILABLE
        
        self.stop_event = threading.Event()
        self.packet_queue = Queue(maxsize=10000)
        self.workers = {}
        self.dispatcher_thread = None
        self._is_active = False

    def _log(self, msg, level="INFO"):
        if self.status_callback:
            self.status_callback(f"[Manager] {msg}", level)
        else:
            print(f"[Manager] {msg}")

    def _get_interfaces(self):
        """Detecta interfaces válidas."""
        try:
            # En Windows, get_if_list devuelve GUIDs complejos
            all_ifaces = get_if_list()
        except Exception as e:
            self._log(f"Error listando interfaces: {e}", "ERROR")
            return []

        valid_ifaces = []
        
        # Filtro simple: Si tiene MAC, suele ser válida para capturar
        for iface in all_ifaces:
            try:
                # Verificar si tiene MAC
                get_if_hwaddr(iface)
                valid_ifaces.append(iface)
            except:
                pass
        
        return valid_ifaces

    def start(self):
        if self._is_active: return
        
        self.stop_event.clear()
        
        # Limpiar cola vieja por si acaso
        with self.packet_queue.mutex:
            self.packet_queue.queue.clear()

        interfaces = self._get_interfaces()
        
        if not interfaces:
            self._log("No se detectaron interfaces de red.", "ERROR")
            return

        self._log(f"Interfaces detectadas: {len(interfaces)}")

        # 1. Iniciar Workers
        for iface in interfaces:
            if iface in self.workers and self.workers[iface].is_alive():
                continue

            worker = SnifferWorker(
                iface, 
                self.packet_queue, 
                self.stop_event, 
                use_pcap=self.use_pcap,
                status_callback=self.status_callback
            )
            self.workers[iface] = worker
            worker.start()

        # 2. Iniciar Dispatcher
        if not self.dispatcher_thread or not self.dispatcher_thread.is_alive():
            self.dispatcher_thread = threading.Thread(target=self._dispatcher_loop, daemon=True)
            self.dispatcher_thread.start()
        
        self._is_active = True

    def stop(self):
        if not self._is_active: return
        
        self._log("Deteniendo todos los sniffers...")
        self.stop_event.set()
        
        # Esperar workers
        for worker in self.workers.values():
            if worker.is_alive():
                worker.join(timeout=0.5)
        
        if self.dispatcher_thread and self.dispatcher_thread.is_alive():
            self.dispatcher_thread.join(timeout=1.0)
            
        self.workers.clear()
        self._is_active = False
        self._log("Captura finalizada.")

    def _dispatcher_loop(self):
        while not self.stop_event.is_set():
            try:
                # Timeout corto para revisar stop_event frecuentemente
                pkt = self.packet_queue.get(timeout=0.1)
                try:
                    self.packet_callback(pkt)
                except Exception:
                    pass
                finally:
                    self.packet_queue.task_done()
            except Empty:
                continue
            except Exception:
                if self.stop_event.is_set(): break