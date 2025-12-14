# ==============================================================================
# core/packet_handler.py
# Procesador COMPLETO: Captura de todo el tráfico de red
# Soporta: TCP, UDP, ICMP, ARP, IPv6, ICMPv6, IGMP, GRE, ESP, AH, SCTP, etc.
# ==============================================================================

from datetime import datetime
from utils.network_utils import resolve_ip
from config import TAG_INSECURE

# Importamos Scapy con TODOS los protocolos
from scapy.all import (
    ARP, DNS, TCP, UDP, ICMP, IP_PROTOS, IP, Ether,
    Raw, Padding, DHCP, BOOTP, NTP, SNMP,
    GRE, ESP, AH, SCTP, L2TP
)
from scapy.layers.inet6 import (
    IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA
)
from scapy.layers.dot11 import Dot11  # WiFi
from scapy.layers.l2 import LLC, SNAP, STP  # Capa 2
from scapy.contrib.igmp import IGMP  # Multicast
from scapy.contrib.ospf import OSPF_Hdr  # Routing

class PacketHandler:

    def __init__(self, controller):
        self.controller = controller
        self.geoip = controller.geoip
        
        # Mapeo extendido de puertos TCP
        self.TCP_PORT_MAP = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS-TCP", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
            587: "SMTP-SUB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            27017: "MongoDB", 5000: "Flask", 9200: "Elasticsearch"
        }
        
        # Mapeo extendido de puertos UDP
        self.UDP_PORT_MAP = {
            53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 69: "TFTP",
            123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
            161: "SNMP", 162: "SNMP-Trap", 500: "IKE",
            514: "Syslog", 520: "RIP", 1194: "OpenVPN",
            1812: "RADIUS", 1813: "RADIUS-Acct", 1900: "SSDP",
            4500: "NAT-T", 5353: "mDNS", 5060: "SIP"
        }
        
        # Protocolos IP adicionales (además de TCP/UDP)
        self.IP_PROTO_MAP = {
            1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
            41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
            88: "EIGRP", 89: "OSPF", 132: "SCTP"
        }

    def _get_tcp_flags_desc(self, flags):
        """Interpreta flags TCP con mayor detalle"""
        f_str = str(flags)
        
        # Handshake normal
        if f_str == 'S': return "[SYN] Inicio de Conexión"
        if f_str == 'SA': return "[SYN-ACK] Conexión Aceptada"
        if f_str == 'A': return "[ACK] Confirmación"
        if f_str == 'PA': return "[PSH-ACK] Transferencia de Datos"
        if f_str == 'FA': return "[FIN-ACK] Cierre Graceful"
        if f_str == 'R': return "[RST] Conexión Rechazada/Reset"
        if f_str == 'RA': return "[RST-ACK] Reset con Confirmación"
        
        # Flags inusuales (potenciales ataques)
        if f_str == 'F': return "[FIN] Cierre sin ACK (Anómalo)"
        if f_str == 'SF': return "[SYN-FIN] Escaneo Xmas (Sospechoso)"
        if f_str == 'U': return "[URG] Datos Urgentes"
        if f_str == '': return "[NULL] Sin Flags (Escaneo NULL)"
        if 'U' in f_str and 'P' in f_str: return "[URG-PSH] Combinación Rara"
        
        return f"[{f_str}] Flags Personalizados"

    def _analyze_dhcp(self, packet):
        """Analiza tráfico DHCP en detalle"""
        if packet.haslayer(DHCP):
            options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
            msg_type = options.get('message-type', 0)
            
            dhcp_types = {
                1: "DISCOVER (Cliente busca servidor)",
                2: "OFFER (Servidor ofrece IP)",
                3: "REQUEST (Cliente acepta IP)",
                4: "DECLINE (Cliente rechaza IP)",
                5: "ACK (Servidor confirma asignación)",
                6: "NAK (Servidor rechaza solicitud)",
                7: "RELEASE (Cliente libera IP)",
                8: "INFORM (Cliente pide configuración)"
            }
            
            desc = dhcp_types.get(msg_type, f"DHCP Tipo {msg_type}")
            
            if packet.haslayer(BOOTP):
                client_mac = packet[BOOTP].chaddr[:6].hex(':')
                requested_ip = options.get('requested_addr', 'N/A')
                desc += f" | MAC: {client_mac}"
                if requested_ip != 'N/A':
                    desc += f" | IP: {requested_ip}"
            
            return "DHCP", 67, desc
        return None

    def _analyze_dns_deep(self, packet):
        """Análisis profundo de DNS"""
        if packet.haslayer(DNS):
            dns = packet[DNS]
            
            # Query
            if dns.qr == 0:
                qname = "Desconocido"
                qtype = "A"
                
                if dns.qd:
                    qname = dns.qd.qname.decode('utf-8', 'ignore').rstrip('.')
                    qtype_code = dns.qd.qtype
                    qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA"}
                    qtype = qtype_map.get(qtype_code, str(qtype_code))
                
                return "DNS", 53, f"Query [{qtype}]: {qname}"
            
            # Response
            else:
                answer_count = dns.ancount
                if answer_count > 0:
                    return "DNS", 53, f"Response: {answer_count} respuesta(s)"
                else:
                    return "DNS", 53, "Response: Sin respuestas (NXDOMAIN)"
        
        return None

    def _analyze_icmp(self, packet):
        """Análisis detallado de ICMP"""
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_type = icmp.type
            icmp_code = icmp.code
            
            # Mapeo de tipos ICMP
            icmp_map = {
                0: "Echo Reply (Pong)",
                3: f"Destination Unreachable (Code {icmp_code})",
                4: "Source Quench",
                5: f"Redirect (Code {icmp_code})",
                8: "Echo Request (Ping)",
                9: "Router Advertisement",
                10: "Router Solicitation",
                11: "Time Exceeded",
                12: "Parameter Problem",
                13: "Timestamp Request",
                14: "Timestamp Reply"
            }
            
            desc = icmp_map.get(icmp_type, f"ICMP Type {icmp_type}")
            
            # Añadir detalles si es ping
            if icmp_type in [8, 0]:
                seq = icmp.seq if hasattr(icmp, 'seq') else 0
                desc += f" | Seq: {seq}"
            
            return "ICMP", "-", desc
        
        return None

    def _analyze_arp(self, packet):
        """Análisis detallado de ARP"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            op = arp.op
            src_ip = arp.psrc
            dst_ip = arp.pdst
            src_mac = arp.hwsrc
            dst_mac = arp.hwdst
            
            if op == 1:  # Request
                return "ARP", "-", f"protocolo ARP a - {dst_ip} | (desde {src_ip} & {src_mac})"
            elif op == 2:  # Reply
                return "ARP", "-", f"protocolo ARP Reply de {src_ip} {src_mac} | (to {dst_ip})"
            else:
                return "ARP", "-", f"ARP Opcode {op}"
        
        return None

    def _analyze_ipv6(self, packet):
        """Análisis de tráfico IPv6 e ICMPv6"""
        if packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            
            # ICMPv6
            if packet.haslayer(ICMPv6EchoRequest):
                return "ICMPv6", "-", "Ping6 Request"
            if packet.haslayer(ICMPv6EchoReply):
                return "ICMPv6", "-", "Ping6 Reply"
            
            # Neighbor Discovery (equivalente a ARP en IPv6)
            if packet.haslayer(ICMPv6ND_NS):
                target = packet[ICMPv6ND_NS].tgt
                return "ICMPv6-ND", "-", f"Neighbor Solicitation: {target}"
            if packet.haslayer(ICMPv6ND_NA):
                target = packet[ICMPv6ND_NA].tgt
                return "ICMPv6-ND", "-", f"Neighbor Advertisement: {target}"
            if packet.haslayer(ICMPv6ND_RS):
                return "ICMPv6-ND", "-", "Router Solicitation"
            if packet.haslayer(ICMPv6ND_RA):
                return "ICMPv6-ND", "-", "Router Advertisement"
            
            # IPv6 genérico
            next_header = ipv6.nh
            return "IPv6", "-", f"Next Header: {next_header}"
        
        return None

    def _analyze_layer2(self, packet):
        """Análisis de protocolos de capa 2 (Ethernet, LLC, STP)"""
        # Spanning Tree Protocol
        if packet.haslayer(STP):
            return "STP", "-", "Spanning Tree Protocol"
        
        # Logical Link Control
        if packet.haslayer(LLC):
            return "LLC", "-", "LLC Frame"
        
        # SNAP (Subnetwork Access Protocol)
        if packet.haslayer(SNAP):
            return "SNAP", "-", "SNAP Frame"
        
        # WiFi (802.11)
        if packet.haslayer(Dot11):
            dot11_type = packet[Dot11].type
            dot11_map = {0: "Management", 1: "Control", 2: "Data"}
            frame_type = dot11_map.get(dot11_type, f"Type {dot11_type}")
            return "WiFi", "-", f"802.11 {frame_type}"
        
        return None

    def _analyze_tunneling(self, packet):
        """Análisis de protocolos de túnel (GRE, L2TP, ESP, AH)"""
        if packet.haslayer(GRE):
            return "GRE", "-", "Generic Routing Encapsulation"
        
        if packet.haslayer(ESP):
            return "ESP", "-", "IPsec Encrypted (ESP)"
        
        if packet.haslayer(AH):
            return "AH", "-", "IPsec Authentication Header"
        
        if packet.haslayer(L2TP):
            return "L2TP", "-", "Layer 2 Tunneling Protocol"
        
        return None

    def _analyze_routing(self, packet):
        """Análisis de protocolos de enrutamiento"""
        if packet.haslayer(OSPF_Hdr):
            ospf_type = packet[OSPF_Hdr].type
            ospf_map = {1: "Hello", 2: "DBD", 3: "LSR", 4: "LSU", 5: "LSAck"}
            return "OSPF", "-", f"OSPF {ospf_map.get(ospf_type, ospf_type)}"
        
        if packet.haslayer(IGMP):
            return "IGMP", "-", "Internet Group Management Protocol"
        
        return None

    def identify_protocol(self, packet):
        """
        IDENTIFICACIÓN COMPLETA DE PROTOCOLOS
        Orden de análisis:
        1. Capa 2 (ARP, STP, WiFi)
        2. Capa 3 (IPv4, IPv6, ICMP, Routing)
        3. Capa 4 (TCP, UDP, SCTP)
        4. Capa 7 (HTTP, DNS, DHCP)
        5. Túneles (GRE, IPsec)
        """
        
        # 1. Protocolos de Capa 2
        result = self._analyze_layer2(packet)
        if result: return result
        
        result = self._analyze_arp(packet)
        if result: return result
        
        # 2. IPv6 y derivados
        result = self._analyze_ipv6(packet)
        if result: return result
        
        # 3. ICMP (debe ir antes que otros análisis IP)
        result = self._analyze_icmp(packet)
        if result: return result
        
        # 4. Protocolos de enrutamiento
        result = self._analyze_routing(packet)
        if result: return result
        
        # 5. DHCP (análisis específico antes que UDP genérico)
        result = self._analyze_dhcp(packet)
        if result: return result
        
        # 6. DNS (análisis específico)
        result = self._analyze_dns_deep(packet)
        if result: return result
        
        # 7. TCP con análisis de handshake
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_p, dst_p = tcp.sport, tcp.dport
            
            service = self.TCP_PORT_MAP.get(dst_p) or self.TCP_PORT_MAP.get(src_p) or "TCP"
            flags_desc = self._get_tcp_flags_desc(tcp.flags)
            
            # HTTP específico
            if service in ["HTTP", "HTTP-Alt"] and len(tcp.payload) > 0:
                try:
                    payload_str = bytes(tcp.payload).decode('utf-8', errors='ignore')
                    first_line = payload_str.split('\r\n')[0]
                    if any(method in first_line for method in ["GET", "POST", "PUT", "DELETE", "HEAD"]):
                        return service, dst_p, f"{flags_desc} | {first_line[:50]}"
                except:
                    pass
            
            # TLS/SSL Handshake
            if service in ["HTTPS", "HTTPS-Alt", "SMTPS", "IMAPS", "POP3S"]:
                if len(tcp.payload) > 5:
                    try:
                        payload_bytes = bytes(tcp.payload)
                        # TLS handshake starts with 0x16 (handshake) + 0x03 (SSL/TLS version)
                        if payload_bytes[0] == 0x16 and payload_bytes[1] == 0x03:
                            return service, dst_p, f"{flags_desc} | TLS Handshake"
                    except:
                        pass
            
            return service, dst_p, f"{flags_desc} | Port {dst_p}"
        
        # 8. UDP genérico
        if packet.haslayer(UDP):
            udp = packet[UDP]
            src_p, dst_p = udp.sport, udp.dport
            service = self.UDP_PORT_MAP.get(dst_p) or self.UDP_PORT_MAP.get(src_p) or "UDP"
            
            payload_size = len(udp.payload)
            return service, dst_p, f"UDP Data | {payload_size} bytes | Port {dst_p}"
        
        # 9. SCTP
        if packet.haslayer(SCTP):
            return "SCTP", "-", "Stream Control Transmission Protocol"
        
        # 10. Túneles
        result = self._analyze_tunneling(packet)
        if result: return result
        
        # 11. Otros protocolos IP
        if packet.haslayer(IP):
            proto_num = packet[IP].proto
            proto_name = self.IP_PROTO_MAP.get(proto_num, f"IP-{proto_num}")
            return proto_name, "-", f"IP Protocol {proto_num}"
        
        # 12. Trama Ethernet pura
        if packet.haslayer(Ether):
            ether = packet[Ether]
            eth_type = ether.type
            
            # Mapeo de EtherTypes comunes
            ethertype_map = {
                0x0800: "IPv4",
                0x0806: "ARP",
                0x86DD: "IPv6",
                0x8100: "VLAN",
                0x88CC: "LLDP",
                0x888E: "802.1X",
                0x8847: "MPLS-Unicast",
                0x8848: "MPLS-Multicast"
            }
            
            eth_proto = ethertype_map.get(eth_type, f"0x{eth_type:04X}")
            return "L2", "-", f"Ethernet Frame | Type: {eth_proto}"
        
        # 13. Desconocido
        return "UNKNOWN", "-", f"Protocolo Desconocido | {len(packet)} bytes"

    def process_packet(self, packet, fast_mode=False):
        """
        PROCESAMIENTO COMPLETO DE PAQUETES
        - Extrae TODAS las direcciones (MAC, IP, IPv6)
        - Identifica TODOS los protocolos
        - Mantiene el objeto packet INTACTO para la IA
        """
        try:
            # --- 1. Extracción de direcciones MAC (Capa 2) ---
            mac_src, mac_dst = "-", "-"
            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
                mac_dst = packet[Ether].dst
            
            # --- 2. Extracción de direcciones IP (Capa 3) ---
            ip_src, ip_dst = "0.0.0.0", "0.0.0.0"
            
            if packet.haslayer(IP):
                ip_src, ip_dst = packet[IP].src, packet[IP].dst
            elif packet.haslayer(IPv6):
                ip_src, ip_dst = packet[IPv6].src, packet[IPv6].dst
            elif packet.haslayer(ARP):
                ip_src, ip_dst = packet[ARP].psrc, packet[ARP].pdst
            
            # --- 3. Identificación del Protocolo ---
            proto_name, port, description = self.identify_protocol(packet)
            size = len(packet)
            
            # --- 4. Resolución DNS (Opcional en modo rápido) ---
            domain = ip_dst
            if not fast_mode and proto_name not in ["ARP", "DHCP", "L2", "WiFi", "STP"]:
                # Solo resolver si es una IP válida
                if ip_dst != "0.0.0.0" and not ip_dst.startswith("ff"):
                    try:
                        domain = resolve_ip(ip_dst)
                    except:
                        pass
            
            # --- 5. GeoIP (Solo para tráfico IP) ---
            country = "Local"
            if proto_name not in ["ARP", "L2", "WiFi", "STP", "LLC", "SNAP"]:
                try:
                    # Priorizar IP origen para ubicación
                    country = self.geoip.get_country_code(ip_src)
                    if country == "-" or country == "Local":
                        country = self.geoip.get_country_code(ip_dst)
                except:
                    country = "-"
            
            # --- 6. Tags de Seguridad ---
            row_tags = set()
            if isinstance(port, int):
                if port in self.controller.INSECURE_PORTS:
                    row_tags.add(TAG_INSECURE)
                
                # Detectar puertos sospechosos (no estándar)
                if port > 49152:  # Puertos dinámicos/privados
                    row_tags.add('high_port')
            
            # Detectar flags TCP sospechosos
            if packet.haslayer(TCP):
                flags_str = str(packet[TCP].flags)
                if flags_str in ['SF', '', 'FPU', 'FSRPAUEC']:  # Escaneos conocidos
                    row_tags.add('suspicious')
            
            # --- 7. Timestamp ---
            try:
                timestamp = datetime.fromtimestamp(float(packet.time))
            except:
                timestamp = datetime.now()
            
            # --- 8. Construcción de Respuesta ---
            table_row = (
                timestamp.strftime('%H:%M:%S'),
                country,
                ip_src,
                ip_dst,
                domain,
                proto_name,
                str(port) if port != "-" else "-",
                size,
                description
            )
            
            result = {
                'packet': packet,        # OBJETO COMPLETO para IA
                'values': table_row,
                'tags': tuple(row_tags),
                'timestamp': timestamp,
                'size': size,
                'protocol': proto_name,
                'mac_src': mac_src,      # Info adicional
                'mac_dst': mac_dst,
                'ip_src': ip_src,
                'ip_dst': ip_dst
            }
            
            return result
            
        except Exception as e:
            # Solo loguear en modo debug
            if hasattr(self.controller, 'DEBUG_MODE') and self.controller.DEBUG_MODE:
                print(f"[PacketHandler] Error: {e}")
            return None
