"""
SPYNET V1.0 - Archivo de Configuración
Centraliza todas las constantes y configuraciones del sistema
"""

import os
import platform

# ==============================================================================
# RUTAS Y DIRECTORIOS
# ==============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) # Raíz del proyecto
ICON_PATH = os.path.join(SCRIPT_DIR, 'assets', 'img')
GEOIP_DB_PATH = os.path.join(SCRIPT_DIR, 'assets', 'geoip', 'GeoLite2-City.mmdb')

# --- ¡CAMBIO AQUÍ! ---
# IA_MODEL_PATH = os.path.join(SCRIPT_DIR, "modelo_ia.pkl") # <-- Ruta antigua
IA_MODEL_PATH = os.path.join(SCRIPT_DIR, "modelo_intrusion_MLP.h5")
IA_SCALER_PATH = os.path.join(SCRIPT_DIR, "scaler_full.pkl") 


# ==============================================================================
# CONFIGURACIÓN DE RED
# ==============================================================================
DEFAULT_NETWORK_RANGE = "192.168.1.0/24"
INSECURE_PORTS_DEFAULT = {80, 21, 23, 25, 110}
COMMON_SCAN_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69,
    80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 464, 500,
    512, 513, 514, 520, 521, 554, 587, 631, 636,
    860, 873, 902, 903, 989, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029,
    1433, 1521, 1701, 1723, 1812, 1813, 1883, 2049,
    2375, 2376, 2483, 2484, 2948, 3260, 3306, 3389,
    3478, 4369, 4786, 5000, 5060, 5061, 5432, 5500,
    5601, 5672, 5683, 5900, 5984, 5985, 5986, 6379,
    6443, 6514, 6667, 7000, 7001, 7077, 7199, 7337,
    7443, 7474, 7547, 8000, 8001, 8008, 8080, 8081,
    8086, 8087, 8161, 8200, 8333, 8443, 8500, 8600,
    8834, 8883, 9000, 9001, 9042, 9090, 9200, 9300,
    9418, 9600, 9999, 10000, 11211, 18080, 27017, 27018,
    27019, 28017, 29015, 50070, 50075
]

# ==============================================================================
# CLASIFICACIÓN DE DOMINIOS
# ==============================================================================
SOCIAL_DOMAINS = ["facebook", "fb.com", "x", "x.com", "instagram", "tiktok", "netflix", "youtube", "spotify", "whatsapp"]
ADULT_DOMAINS = ["xvideos", "pornhub", "xnxx", "xhamster"]

# ==============================================================================
# VENDOR MAC ADDRESS PREFIXES
# ==============================================================================
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:1A:A0": "Cisco",
    "00:0B:BE": "Cisco",
    "00:13:19": "Cisco",
    "F0:18:98": "Apple",
    "A4:5E:60": "Apple",
    "90:27:E4": "Apple",
    "7C:D1:C3": "Samsung",
    "5C:F9:38": "Samsung",
    "D0:57:7B": "Samsung",
    "EC:23:3D": "Huawei",
    "AC:85:3D": "Huawei",
    "60:A4:4C": "Huawei",
    "F8:B1:56": "Dell",
    "A4:4C:C8": "Dell",
    "C8:B5:AD": "Dell",
    "3C:97:0E": "Lenovo",
    "C8:5B:76": "Lenovo",
    "F4:F2:6D": "TP-Link",
    "68:FF:7B": "TP-Link",
    "AC:84:C6": "TP-Link",
    "F0:9F:C2": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "4C:5E:0C": "MikroTik",
    "CC:2D:E0": "MikroTik",
    "3C:5A:B4": "Intel",
    "00:1C:C0": "Intel",
    "F8:16:54": "Intel",
    "BC:60:A7": "Sony",
    "00:1D:0D": "Sony",
    "00:22:48": "Microsoft",
    "60:45:CB": "Microsoft",
    "3C:07:71": "Acer",
    "04:48:9A": "Acer",
    "F0:76:1C": "Acer",
    "e0:2e:0b": "Acer",
    "C8:60:00": "ASUS",
    "50:46:5D": "ASUS",
    "D8:50:E6": "ASUS",
    "B8:CA:3A": "HP",
    "3C:D9:2B": "HP",
    "F4:CE:46": "HP",
    "EC:8A:4C": "MSI",
    "40:16:7E": "MSI",
    "00:26:AB": "MSI",
    "5C:F9:DD": "Toshiba",
    "00:1B:D3": "Toshiba",
    "C4:17:FE": "Toshiba",
    "00:23:54": "LG",
    "C8:2A:14": "LG",
    "90:E7:C4": "LG",
    "00:24:E8": "Sony",
    "BC:60:A7": "Sony",
    "00:1D:0D": "Sony",
    "38:2C:4A": "Samsung (Laptops)",
    "E8:50:8B": "Samsung (Laptops)",
    "F4:09:D8": "Samsung (Laptops)",
    "3C:97:0E": "Lenovo",
    "C8:5B:76": "Lenovo",
    "A0:2B:B8": "Lenovo"
}

# ==============================================================================
# CONFIGURACIÓN DE GRÁFICOS
# ==============================================================================
GRAPH_UPDATE_INTERVAL = 1000  # ms
MAX_PLOT_POINTS = 300
GRAPH_FIGURE_SIZE = (5.5, 3.8)
GRAPH_DPI = 100

# ==============================================================================
# CONFIGURACIÓN DE IA
# ==============================================================================
AI_CONTAMINATION = 0.01
AI_CALIBRATION_SIZE = 500

# ==============================================================================
# CONFIGURACIÓN DE UI
# ==============================================================================
WINDOW_TITLE = "SPYNET Beta V1.0.0"
WINDOW_GEOMETRY = "900x600"
WINDOW_BG_COLOR = "#3d4348"
SECONDARY_BG_COLOR = "#5b5f61"
TEXT_COLOR = '#ecf0f1'
ACCENT_COLOR = "#5d5f62"

# Selección de fuente según el sistema operativo
if platform.system() == "Windows":
    MAIN_FONT = ("Segoe UI", 10)
    BOLD_FONT = ("Segoe UI", 10, "bold")
elif platform.system() == "Darwin":  # macOS
    MAIN_FONT = ("Helvetica Neue", 12)
    BOLD_FONT = ("Helvetica Neue", 12, "bold")
else:  # Linux y otros
    MAIN_FONT = ("Ubuntu", 10)
    BOLD_FONT = ("Ubuntu", 10, "bold")

# ==============================================================================
# PAQUETES REQUERIDOS
# ==============================================================================
REQUIRED_PACKAGES = {
    'scapy': 'scapy',
    'psutil': 'psutil',
    'matplotlib': 'matplotlib',
    'PIL': 'Pillow',
    'maxminddb': 'maxminddb',
    'requests': 'requests',
    'networkx': 'networkx',
    'sklearn': 'scikit-learn',
    'numpy': 'numpy',
    'joblib': 'joblib',
    #'pcapy': 'pcapy',
    #'tensorflow': 'tensorflow',
    'pandas': 'pandas',
    #'keras': 'keras',
    'h5py': 'h5py',
}

# ==============================================================================
# CONFIGURACIÓN DE CAPTURA PCAP
# ==============================================================================
PCAP_FILENAME_FORMAT = "spynet_capture_%Y%m%d_%H%M%S.pcap"

# ==============================================================================
# CONFIGURACIÓN DE EXPORTACIÓN
# ==============================================================================
CSV_EXPORT_FORMAT = "trafico_exportado_%Y%m%d_%H%M%S.csv"
SESSION_FILE_EXTENSION = ".spynet"
DASHBOARD_SNAPSHOT_FORMAT = "dashboard_%Y%m%d_%H%M%S.png"

# ==============================================================================
# TIMEOUTS Y LÍMITES
# ==============================================================================
NETWORK_SCAN_TIMEOUT = 0  # segundos
PORT_SCAN_TIMEOUT = 0  # segundos
SNIFF_TIMEOUT = 0         # segundos

# ==============================================================================
# TAGS DE TABLA
# ==============================================================================
TAG_INSECURE = 'insecure'
TAG_SOCIAL = 'social'
TAG_ADULT = 'adult'
TAG_ANOMALY = 'anomaly'

# ==============================================================================
# VIRUSTOTAL
# ==============================================================================
VIRUSTOTAL_API_KEY_DEFAULT = ""
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"







