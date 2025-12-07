# ==============================================================================
# core/packet_handler.py
# Procesador de paquetes: TCP Handshake, ARP, DNS y Metadatos
# ==============================================================================

from datetime import datetime
from utils.network_utils import resolve_ip
from config import TAG_INSECURE

# Importamos Scapy
from scapy.all import ARP, DNS, TCP, UDP, ICMP, IP_PROTOS, IP, Ether
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply

class PacketHandler:

    def __init__(self, controller):
        self.controller = controller
        self.geoip = controller.geoip
        
        # Diccionarios optimizados para velocidad
        self.TCP_PORT_MAP = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 110: "POP3", 143: "IMAP", 53: "DNS-TCP",
            3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        self.UDP_PORT_MAP = {
            53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 123: "NTP",
            161: "SNMP", 500: "IKE", 1900: "SSDP", 443: "QUIC"
        }

    def _get_tcp_flags_desc(self, flags):
        """
        Interpreta los flags TCP para identificar el enlace de 3 vías.
        S = SYN, A = ACK, F = FIN, R = RST, P = PSH
        """
        # Convertir el objeto FlagValue de Scapy a string
        f_str = str(flags)
        
        # Detectar Handshake y Estados
        if f_str == 'S': return "[SYN] Conexión Solicitada"
        if f_str == 'SA': return "[SYN, ACK] Conexión Aceptada"
        if f_str == 'A': return "[ACK] Conexión Establecida"
        if f_str == 'PA': return "[PSH, ACK] Transfiriendo Datos"
        if f_str == 'FA': return "[FIN, ACK] Cerrando Conexión"
        if f_str == 'R': return "[RST] Conexión Rechazada"
        if f_str == 'RA': return "[RST, ACK] Reinicio de Conexión"
        
        return f"Flags: [{f_str}]"

    def identify_protocol(self, packet):
        """
        Analiza el paquete para extraer: (Protocolo, Puerto, Descripción Detallada)
        """
        # 1. ---- ARP (Capa de Enlace/Red) ----
        if packet.haslayer(ARP):
            op = packet[ARP].op
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            
            # ARP Request (Who has?)
            if op == 1:
                return "ARP", "-", f"¿Quién tiene {dst_ip}? Pregunta {src_ip}"
            # ARP Reply (Is at)
            elif op == 2:
                src_mac = packet[ARP].hwsrc
                return "ARP", "-", f"{src_ip} está en {src_mac}"
            return "ARP", "-", "Trama ARP Genérica"

        # 2. ---- Capa 4: TCP (Con Handshake) ----
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_p, dst_p = tcp.sport, tcp.dport
            
            # Identificar servicio
            service = self.TCP_PORT_MAP.get(dst_p) or self.TCP_PORT_MAP.get(src_p) or "TCP"
            
            # Identificar estado del enlace (Flags)
            flags_desc = self._get_tcp_flags_desc(tcp.flags)
            
            # HTTP Específico (si vemos payload en puerto 80/8080)
            if service in ["HTTP", "HTTP-Alt"] and len(tcp.payload) > 0:
                try:
                    payload_str = bytes(tcp.payload).decode('utf-8', errors='ignore').split('\r\n')[0]
                    if "GET" in payload_str or "POST" in payload_str or "HTTP" in payload_str:
                        return service, dst_p, f"{flags_desc} | {payload_str[:40]}..."
                except:
                    pass

            return service, dst_p, f"{flags_desc} Seq:{tcp.seq}"

        # 3. ---- Capa 4: UDP ----
        if packet.haslayer(UDP):
            udp = packet[UDP]
            src_p, dst_p = udp.sport, udp.dport
            
            # DNS Detallado
            if packet.haslayer(DNS):
                if packet[DNS].qr == 0:
                    # Query
                    qname = "Desconocido"
                    if packet[DNS].qd:
                        qname = packet[DNS].qd.qname.decode('utf-8', 'ignore').rstrip('.')
                    return "DNS", 53, f"Consulta: {qname}"
                else:
                    # Response
                    return "DNS", 53, "Respuesta DNS"

            service = self.UDP_PORT_MAP.get(dst_p) or self.UDP_PORT_MAP.get(src_p) or "UDP"
            return service, dst_p, f"Datos UDP ({len(packet)} bytes)"

        # 4. ---- ICMP (Ping) ----
        if packet.haslayer(ICMP):
            t = packet[ICMP].type
            if t == 8: return "ICMP", "-", "Ping Request"
            if t == 0: return "ICMP", "-", "Ping Reply"
            if t == 3: return "ICMP", "-", "Destino Inalcanzable"
            return "ICMP", "-", f"Tipo {t}"

        # 5. ---- IPv6 / ICMPv6 ----
        if packet.haslayer(IPv6):
            if packet.haslayer(ICMPv6EchoRequest): return "ICMPv6", "-", "Ping v6 Request"
            if packet.haslayer(ICMPv6EchoReply): return "ICMPv6", "-", "Ping v6 Reply"
            return "IPv6", "-", "Tráfico IPv6"

        # 6. ---- Default IP ----
        if packet.haslayer(IP):
            proto_id = packet[IP].proto
            proto_str = IP_PROTOS.get(proto_id, str(proto_id))
            return proto_str, "-", f"Protocolo IP {proto_id}"

        return "ETHERNET", "-", "Trama L2 / No IP"

    def process_packet(self, packet, fast_mode=False):
        """
        Procesa el paquete, extrae datos y retorna el diccionario.
        NO encola directamente a la IA (eso lo hace el controlador).
        """
        try:
            # --- 1. Extracción de Direcciones ---
            ip_src, ip_dst = "0.0.0.0", "0.0.0.0"
            
            if packet.haslayer(IP):
                ip_src, ip_dst = packet[IP].src, packet[IP].dst
            elif packet.haslayer(IPv6):
                ip_src, ip_dst = packet[IPv6].src, packet[IPv6].dst
            elif packet.haslayer(ARP):
                ip_src, ip_dst = packet[ARP].psrc, packet[ARP].pdst

            # Si no hay IPs (ej: trama ethernet pura sin IP), ignoramos o ponemos valores default
            if ip_src == "0.0.0.0" and not packet.haslayer(ARP):
                # Opcional: Procesar tramas no-IP si quieres
                pass

            # --- 2. Identificación del Protocolo ---
            proto_name, port, description = self.identify_protocol(packet)
            size = len(packet)

            # --- 3. Resolución DNS ---
            domain = ip_dst
            # Evitamos resolver si es ARP, modo rápido o IP privada (opcional)
            if not fast_mode and proto_name not in ["ARP", "DHCP", "DNS"]:
                try:
                    # Usamos un try agresivo para no frenar el tráfico
                    domain = resolve_ip(ip_dst) 
                except:
                    pass

            # --- 4. GeoIP ---
            country = "LOC"
            if proto_name != "ARP":
                try:
                    country = self.geoip.get_country_code(ip_src)
                except:
                    country = "-"

            # --- 5. Tags de Seguridad ---
            row_tags = set()
            if isinstance(port, int) and port in self.controller.INSECURE_PORTS:
                row_tags.add(TAG_INSECURE)

            # --- 6. Timestamp ---
            try:
                # Usamos packet.time (float) convertido a datetime
                timestamp = datetime.fromtimestamp(float(packet.time))
            except:
                timestamp = datetime.now()

            # --- 7. Construcción de Respuesta ---
            # Valores para la tabla visual (Treeview)
            table_row = (
                timestamp.strftime('%H:%M:%S'),
                country,
                ip_src,
                ip_dst,
                domain,
                proto_name,
                str(port),
                size,
                description # Aquí va el detalle del Handshake/ARP
            )

            # Diccionario completo para el Controlador y la IA
            result = {
                'packet': packet,        # OBJETO PURO (Vital para IA)
                'values': table_row,     # UI
                'tags': tuple(row_tags), # Colores UI
                'timestamp': timestamp,
                'size': size,
                'protocol': proto_name
            }

            return result

        except Exception as e:
            # Imprimir error solo si es crítico, para no ensuciar la consola
            # print(f"[Handler Error] {e}") 
            return None