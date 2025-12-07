# ==============================================================================
# ui/devices_tab.py
# Configuración de la pestaña de dispositivos y lógica de escaneo
# ==============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, Text
import threading
import socket
from ui.dialogs import Tooltip
from config import COMMON_SCAN_PORTS, NETWORK_SCAN_TIMEOUT, PORT_SCAN_TIMEOUT, ACCENT_COLOR

# --- ¡ESTA ES LA CORRECCIÓN PARA EL AttributeError! ---
# Importamos la función 'get_mac_vendor' desde utils
from utils.network_utils import get_mac_vendor

class DevicesTab:
    """
    Clase que gestiona la pestaña 'Dispositivos en Red' y su lógica de escaneo.
    """

    def __init__(self, controller, notebook):
        self.controller = controller
        self.frame = tk.Frame(notebook, bg='#ffffff')
        notebook.add(self.frame, text="SIEM")
        notebook.add(self.frame, text="Dispositivos en Red")
        notebook.tab(notebook.index(self.frame), state='normal')
        self.setup_devices_table(self.frame)

    def setup_devices_table(self, parent_frame):
        """
        Crea la tabla para mostrar los dispositivos encontrados en la red.
        """
        frame = tk.Frame(parent_frame, bg='#ffffff')
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top_panel = tk.Frame(frame, bg='#ffffff')
        top_panel.pack(fill=tk.X, pady=(0, 10))

        tk.Label(frame, text=" Haz clic en el ícono de la lupa para escanear la red", font=("Segoe UI", 10), bg='#ffffff', fg='#7f8c8d').pack(pady=(0, 10))

        scan_ports_button = tk.Button(top_panel, text="Escanear Puertos del Host Seleccionado", command=self.scan_selected_host_ports, bg=ACCENT_COLOR, fg="white", relief="flat", font=("Segoe UI", 9, "bold"))
        scan_ports_button.pack(side=tk.RIGHT, padx=5)
        Tooltip(scan_ports_button, "Realiza un escaneo de puertos comunes en el dispositivo seleccionado en la tabla.")

        device_cols = ("IP", "MAC", "Fabricante", "Nombre del Host", "Estado")
        self.controller.devices_tree = ttk.Treeview(frame, columns=device_cols, show="headings", height=15)
        for col in device_cols: 
            self.controller.devices_tree.heading(col, text=col)
        
        self.controller.devices_tree.column("IP", width=120)
        self.controller.devices_tree.column("MAC", width=140)
        self.controller.devices_tree.column("Fabricante", width=150)
        self.controller.devices_tree.column("Nombre del Host", width=200)
        self.controller.devices_tree.column("Estado", width=80, anchor='center')
        
        device_menu = tk.Menu(self.controller.devices_tree, tearoff=0)
        #device_menu.add_command(label="Bloquear IP", command=self.controller.bloquear_ip_seleccionada)
        #device_menu.add_command(label="Desbloquear IP", command=self.controller.desbloquear_ip_seleccionada)

        def mostrar_menu(event):
            item = self.controller.devices_tree.identify_row(event.y)
            if item:
                self.controller.devices_tree.selection_set(item)
                device_menu.post(event.x_root, event.y_root)

        self.controller.devices_tree.bind("<Button-3>", mostrar_menu)

        d_v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.controller.devices_tree.yview)
        d_v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.controller.devices_tree.pack(fill=tk.BOTH, expand=True)

    def scan_network(self):
        """
        Inicia el escaneo de la red (inicia el hilo de trabajo).
        """
        for i in self.controller.devices_tree.get_children():
            self.controller.devices_tree.delete(i)

        ventana_carga = Toplevel(self.controller.window)
        ventana_carga.title("Escaneando Red...")
        ventana_carga.geometry("350x120")
        ventana_carga.resizable(False, False)
        ventana_carga.configure(bg="#34495e")
        ventana_carga.transient(self.controller.window)
        ventana_carga.grab_set()

        tk.Label(ventana_carga, text="Buscando dispositivos en la red...", font=("Segoe UI", 11), bg="#34495e", fg="white").pack(pady=(15, 10))

        progress_bar = ttk.Progressbar(ventana_carga, orient="horizontal", length=300, mode="indeterminate")
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        threading.Thread(target=self.scan_worker, args=(ventana_carga, progress_bar), daemon=True).start()

    def scan_worker(self, ventana_carga, progress_bar):
        """
        Hilo de trabajo para el escaneo de red.
        Pausa el sniffer principal para evitar conflictos de sockets.
        """
        
        was_monitoring = False
        if self.controller.monitoring_active and not self.controller.is_paused:
            was_monitoring = True
            print("[Scan INFO] Pausando el sniffer principal para el escaneo ARP...")
            self.controller.window.after(0, self.controller.toggle_pause)
            threading.Event().wait(0.5) 

        try:
            network_range = self.controller.get_network_range()
            
            print(f"[Scan INFO] Escaneando {network_range} con Scapy (srp)...")
            
            answered_list = self.controller.scapy_srp(
                self.controller.scapy_Ether(dst="ff:ff:ff:ff:ff:ff") / self.controller.scapy_ARP(pdst=network_range),
                timeout=NETWORK_SCAN_TIMEOUT,
                verbose=False
            )[0]
            print(f"[Scan INFO] Escaneo completado. {len(answered_list)} dispositivos encontrados.")

            devices = []
            for s, r in answered_list:
                ip = r.psrc
                mac = r.hwsrc
                
                # --- ¡ESTA ES LA CORRECCIÓN PARA EL AttributeError! ---
                # Ya no usamos 'self.controller.get_mac_vendor'
                vendor = get_mac_vendor(mac) 
                
                hostname = self.controller.resolve_ip(ip)
                if hostname == ip:
                    hostname = "No resuelto"
                status = 'Activo'
                devices.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'hostname': hostname, 'status': status})

            self.controller.window.after(0, self.update_devices_table, devices)

        except Exception as e:
            if "10013" in str(e):
                err_msg = "Error de Permisos (10013).\n\nIncluso como Admin, tu Antivirus o Firewall (Windows Defender, ESET, Avast, etc.) está bloqueando el escaneo ARP.\n\nIntenta desactivar temporalmente tu Antivirus y vuelve a escanear."
                self.controller.window.after(0, lambda: messagebox.showerror("Error de Permisos", err_msg))
            else:
                err_msg = f"Error al escanear: {e}\n\n¿Estás seguro de que ejecutas como administrador?"
                self.controller.window.after(0, lambda: messagebox.showerror("Error de Escaneo", err_msg))
        
        finally:
            if was_monitoring:
                print("[Scan INFO] Reanudando el sniffer principal...")
                self.controller.window.after(0, self.controller.toggle_pause)
                
            try:
                ventana_carga.after(0, progress_bar.stop)
                ventana_carga.after(0, ventana_carga.destroy)
            except Exception:
                pass

    def update_devices_table(self, devices):
        """
        Actualiza la tabla de dispositivos con los resultados del escaneo.
        """
        for device in devices: 
            self.controller.devices_tree.insert('', 'end', values=(device['ip'], device['mac'], device['vendor'], device['hostname'], device['status']))
        messagebox.showinfo("Escaneo Completado", f"Se encontraron {len(devices)} dispositivos.", parent=self.controller.window)
        
    def scan_selected_host_ports(self):
        """
        Inicia un escaneo de puertos en el host seleccionado.
        """
        selected_item = self.controller.devices_tree.focus()
        if not selected_item:
            messagebox.showwarning("Sin Selección", "Por favor, selecciona un dispositivo de la lista para escanear.")
            return

        device_ip = self.controller.devices_tree.item(selected_item)['values'][0]
        
        common_ports = COMMON_SCAN_PORTS # Desde config

        scan_window = Toplevel(self.controller.window)
        scan_window.title(f"Escaneando Puertos en {device_ip}")
        scan_window.geometry("400x300")
        scan_window.configure(bg="#2c3e50")
        tk.Label(scan_window, text=f"Escaneando puertos en {device_ip}...", font=("Segoe UI", 12), bg="#2c3e50", fg="white").pack(pady=10)
        
        results_text = Text(scan_window, bg="#34495e", fg="white", font=("Consolas", 10), relief="flat")
        results_text.pack(expand=True, fill="both", padx=10, pady=10)
        results_text.insert(tk.END, "Iniciando escaneo...\n\n")

        def port_scan_worker():
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(PORT_SCAN_TIMEOUT) # Desde config
                    result = sock.connect_ex((device_ip, port))
                    status = "Abierto" if result == 0 else "Cerrado"
                    if result == 0:
                        open_ports.append(port)
                    
                    scan_window.after(0, lambda p=port, s=status: results_text.insert(tk.END, f"Puerto {p}: {s}\n"))
                    scan_window.after(0, lambda: results_text.see(tk.END))
                    sock.close()
                except socket.error as e:
                    scan_window.after(0, lambda p=port, err=e: results_text.insert(tk.END, f"Puerto {p}: Error - {err}\n"))

            final_message = f"\nEscaneo completado. Puertos abiertos encontrados: {open_ports if open_ports else 'Ninguno'}"
            scan_window.after(0, lambda: results_text.insert(tk.END, final_message))

        threading.Thread(target=port_scan_worker, daemon=True).start()