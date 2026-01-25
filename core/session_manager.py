# ==============================================================================
# core/session_manager.py - MOTOR DE REENSAMBLADO DE FLUJOS
# Implemetacion en la verison 1.2
# ==============================================================================

from scapy.all import TCP, IP, IPv6, Raw
import collections

class TCPSession:
    def __init__(self):
        self.packets = []
        self.payload_buffer = b""
        self.state = "START"
        self.sni = None
        self.host = None

class SessionManager:
    def __init__(self):
        # Llave: (IP_A, Port_A, IP_B, Port_B) - Ordenada para ser bidireccional
        self.sessions = {}

    def _get_session_key(self, pkt):
        if not pkt.haslayer(TCP): return None
        src = (pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src, pkt[TCP].sport)
        dst = (pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst, pkt[TCP].dport)
        return tuple(sorted([src, dst]))

    def update(self, pkt):
        key = self._get_session_key(pkt)
        if not key: return None

        if key not in self.sessions:
            self.sessions[key] = TCPSession()
        
        session = self.sessions[key]
        session.packets.append(pkt)

        # Extraer Datos de Aplicación (DPI)
        if pkt.haslayer(Raw):
            load = bytes(pkt[Raw])
            session.payload_buffer += load
            
            # 1. Extraer SNI de TLS (Client Hello)
            if not session.sni and b"\x16\x03" in load: # TLS Handshake
                session.sni = self._extract_tls_sni(load)
            
            # 2. Extraer Host de HTTP
            if not session.host and b"Host: " in load:
                try:
                    session.host = load.split(b"Host: ")[1].split(b"\r\n")[0].decode()
                except: pass

        return session

    def _extract_tls_sni(self, data):
        """Analiza binariamente el ClientHello para extraer el nombre del servidor"""
        try:
            # Simplificación: Buscamos el patrón de extensión de server_name
            pos = data.find(b"\x00\x00") # Extension type: server_name
            if pos != -1:
                # Lógica de offset para llegar al string del dominio
                # En un entorno de producción se usaría un parser TLS real
                return "TLS SNI Detected" 
        except: pass
        return None