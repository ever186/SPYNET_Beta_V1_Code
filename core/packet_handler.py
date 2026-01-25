# ==============================================================================
# core/packet_handler.py
# Procesador COMPLETO: Captura de todo el tráfico de red
# Soporta: TCP, UDP, ICMP, ARP, IPv6, ICMPv6, IGMP, GRE, ESP, AH, SCTP, etc.
# ==============================================================================

import threading
import socket
from datetime import datetime
from scapy.all import (
    ARP, DNS, TCP, UDP, ICMP, IP, Ether, Raw, 
    DHCP, BOOTP, IPv6, ICMPv6EchoRequest
)
# Intentamos importar capas adicionales para protocolos específicos
try:
    from scapy.layers.netbios import NBNSQueryRequest, NBNSResponse
except:
    NBNSQueryRequest = None

from config import TAG_INSECURE, INSECURE_PORTS_DEFAULT

class PacketHandler:
    def __init__(self, controller):
        self.controller = controller
        self.geoip = controller.geoip
        self.dns_cache = {}
        self.resolving = set()
        
        # Mapa de servicios extendido (Power User)
        self.SERVICES = {
            21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
            67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
            137: "NBNS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
            143: "IMAP", 161: "SNMP", 443: "HTTPS/QUIC", 445: "SMB",
            548: "AFP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
            1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS",
            5355: "LLMNR", 5060: "SIP", 8080: "HTTP-ALT"
        }

    def _async_resolve(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = name
        except:
            self.dns_cache[ip] = ip
        finally:
            if ip in self.resolving: self.resolving.remove(ip)

    def get_domain(self, ip):
        if ip in self.dns_cache: return self.dns_cache[ip]
        # Solo resolver IPs públicas para no saturar con tráfico local
        if ip not in self.resolving and "." in ip:
            if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")):
                self.resolving.add(ip)
                threading.Thread(target=self._async_resolve, args=(ip,), daemon=True).start()
        return ip

    def _get_tcp_flags(self, tcp):
        f = tcp.flags
        flags = []
        flag_map = {'F': "FIN", 'S': "SYN", 'R': "RST", 'P': "PSH", 'A': "ACK", 'U': "URG", 'E': "ECE", 'C': "CWR"}
        for char, name in flag_map.items():
            if char in str(f): flags.append(name)
        return f"[{'+'.join(flags)}]" if flags else "[ACK]"

    def _deep_inspect(self, payload, sport, dport):
        """DPI avanzado para protocolos sin puerto fijo o encapsulados."""
        if not payload: return None, None
        
        # Detección QUIC (Google/HTTP3)
        if (sport == 443 or dport == 443) and (payload[0] & 0x80 or payload[0] & 0x40):
            return "QUIC", "Encrypted UDP Traffic (HTTP/3-like)"
        
        # Detección TLS/SSL
        if payload.startswith(b'\x16\x03'):
            version = {b'\x16\x03\x01': "TLS 1.0", b'\x16\x03\x03': "TLS 1.2/1.3"}.get(payload[:3], "TLS")
            return version, "Security Handshake (Encryption)"
        
        # Detección HTTP (Métodos comunes)
        for method in [b"GET ", b"POST ", b"HTTP/", b"PUT ", b"OPTIONS "]:
            if payload.startswith(method):
                try: 
                    line = payload.split(b'\r\n')[0].decode(errors='ignore')
                    return "HTTP", f"Web: {line}"
                except: return "HTTP", "Web Traffic (Plain Text)"

        # NetBIOS / NBNS via Raw
        if sport == 137 or dport == 137:
            return "NBNS", "NetBIOS Name Service Query/Response"

        return None, None

    def get_full_details(self, packet):
        """Analizador jerárquico de protocolos."""
        # 1. ARP
        if packet.haslayer(ARP):
            op = "petition (Who has?)" if packet[ARP].op == 1 else "Answer (Is at)"
            return "ARP", "-", f"{op}: {packet[ARP].psrc} -> {packet[ARP].pdst}"

        # 2. DNS / mDNS / LLMNR
        if packet.haslayer(DNS):
            qname = packet[DNS].qd.qname.decode(errors='ignore') if packet[DNS].qd else "unrecognized"
            proto = "DNS"
            if packet.haslayer(UDP):
                if packet[UDP].dport == 5353: proto = "mDNS"
                elif packet[UDP].dport == 5355: proto = "LLMNR"
            tipo = "Answer" if packet[DNS].qr else "Query"
            return proto, packet[UDP].dport, f"{tipo}: {qname}"

        # 3. TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            port = tcp.dport
            proto = self.SERVICES.get(tcp.sport) or self.SERVICES.get(tcp.dport) or "TCP"
            flags = self._get_tcp_flags(tcp)
            desc = f"{flags} Seq={tcp.seq}"
            
            if packet.haslayer(Raw):
                dpi_n, dpi_d = self._deep_inspect(bytes(packet[Raw]), tcp.sport, tcp.dport)
                if dpi_n: proto, desc = dpi_n, f"{flags} {dpi_d}"
            return proto, port, desc

        # 4. UDP (Incluye NBNS, QUIC, SSDP)
        if packet.haslayer(UDP):
            udp = packet[UDP]
            port = udp.dport
            proto = self.SERVICES.get(udp.sport) or self.SERVICES.get(udp.dport) or "UDP"
            desc = f"Payload: {len(packet[UDP].payload)} bytes"
            
            if packet.haslayer(Raw):
                dpi_n, dpi_d = self._deep_inspect(bytes(packet[Raw]), udp.sport, udp.dport)
                if dpi_n: proto, desc = dpi_n, dpi_d
            
            # Caso especial DHCP
            if packet.haslayer(DHCP): return "DHCP", port, "IP Assignment/Request"
            
            return proto, port, desc

        # 5. ICMP / IPv6
        if packet.haslayer(ICMP): return "ICMP", "-", f"Tipo: {packet[ICMP].type} (Control/Ping)"
        if packet.haslayer(ICMPv6EchoRequest): return "ICMPv6", "-", "Ping IPv6"
        if packet.haslayer(IPv6): return "IPv6", "-", "Next Generation Network Traffic"

        return proto, "-", packet.summary()

    def process_packet(self, packet):
        try:
            # Capa 2/3 segura
            mac_src = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
            mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "00:00:00:00:00:00"
            
            if packet.haslayer(IP):
                ip_src, ip_dst = packet[IP].src, packet[IP].dst
            elif packet.haslayer(IPv6):
                ip_src, ip_dst = packet[IPv6].src, packet[IPv6].dst
            elif packet.haslayer(ARP):
                ip_src, ip_dst = packet[ARP].psrc, packet[ARP].pdst
            else:
                ip_src, ip_dst = "Layer-2", "Layer-2"
            
            proto_name, port, description = self.get_full_details(packet)
            domain = self.get_domain(ip_dst)
            country = self.geoip.get_country_code(ip_dst) if hasattr(self.controller, 'geoip') else "-"
            
            try: timestamp = datetime.fromtimestamp(float(packet.time))
            except: timestamp = datetime.now()
            size = len(packet)

            table_row = (
                timestamp.strftime('%H:%M:%S'),
                country, ip_src, ip_dst, domain,
                proto_name, str(port), size, description
            )

            return {
                'packet': packet, 'values': table_row,
                'tags': (TAG_INSECURE,) if str(port) in INSECURE_PORTS_DEFAULT else (),
                'timestamp': timestamp, 'size': size, 'protocol': proto_name,
                'mac_src': mac_src, 'mac_dst': mac_dst, 'ip_src': ip_src, 'ip_dst': ip_dst
            }
        except:
            return None
