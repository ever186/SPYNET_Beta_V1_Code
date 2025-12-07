# ==============================================================================
# utils/network_utils.py
# Funciones de red (resolver IPs)
# ==============================================================================

import socket
import ipaddress
import platform
import subprocess
import os
from tkinter import messagebox
from config import DEFAULT_NETWORK_RANGE, MAC_VENDORS

from scapy.all import ARP, Ether, srp

def scan_network():
    """
    Escaneo ARP para descubrir usuarios en la red.
    """
    network = get_network_range()
    print("[+] Escaneando red:", network)

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_mac_vendor(mac)

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor
        })

    return devices

def get_local_ip():
    """
    Intenta obtener la IP local de la interfaz conectada.
    """
    s = None
    try:
        # Crea un socket UDP que no necesita conectarse realmente
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Intenta conectarse a una dirección externa conocida (solo para obtener la IP local)
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
        return local_ip
    except Exception:
        # Fallback si falla la conexión a 8.8.8.8 (ej. sin conexión a internet)
        # Intenta obtener el hostname local (menos fiable)
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return None
    finally:
        if s:
            s.close()


def get_network_range():
    """
    Obtiene el rango de red local (ej: 192.168.1.0/24).
    """
    local_ip = get_local_ip()
    if local_ip:
        try:
            # Asume una máscara /24 (clase C común) para el escaneo local
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except Exception:
            return DEFAULT_NETWORK_RANGE
    return DEFAULT_NETWORK_RANGE # Fallback desde config

def resolve_ip_with_cache(ip_address, cache, max_size=1000):
    """
    Resuelve IPs usando caché para evitar consultas DNS repetidas.
    """
    if ip_address in cache:
        return cache[ip_address]
    
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        
        # Limitar tamaño del caché
        if len(cache) >= max_size:
            # Eliminar la entrada más antigua
            cache.pop(next(iter(cache)))
        
        cache[ip_address] = hostname
        return hostname
    except Exception:
        cache[ip_address] = ip_address
        return ip_address
    
def resolve_ip(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except Exception:
        return ip_address

def get_mac_vendor(mac):
    return MAC_VENDORS.get(mac[:8].lower(), "Desconocido")

def bloquear_ip(ip, parent_window=None):
    if platform.system() == "Windows":
        comando = f'netsh advfirewall firewall add rule name="SPYNET Bloqueo {ip}" dir=in action=block remoteip={ip}'
    else:
        comando = f'sudo iptables -A INPUT -s {ip} -j DROP'

    try:
        subprocess.run(comando, shell=True, check=True, capture_output=True, text=True)
        messagebox.showinfo("IP Bloqueada", f"La IP {ip} fue bloqueada correctamente.", parent=parent_window)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo bloquear la IP {ip}.\nError: {e.stderr}", parent=parent_window)

def desbloquear_ip(ip, parent_window=None):
    if platform.system() == "Windows":
        comando = f'netsh advfirewall firewall delete rule name="SPYNET Bloqueo {ip}"'
    else:
        comando = f'sudo iptables -D INPUT -s {ip} -j DROP'

    try:
        subprocess.run(comando, shell=True, check=True, capture_output=True, text=True)
        messagebox.showinfo("IP Desbloqueada", f"La IP {ip} fue desbloqueada correctamente.", parent=parent_window)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo desbloquear la IP {ip}.\nError: {e.stderr}", parent=parent_window)


