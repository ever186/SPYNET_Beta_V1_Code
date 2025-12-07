# SPYNET_Beta_V1_Code
## 🕸️ SPYNET Beta V1.0
<div align="center">
Mostrar imagen
Analizador de Red Potenciado por IA - Network Security Analyzer
Mostrar imagen
Mostrar imagen
Mostrar imagen
Monitoreo de red en tiempo real con detección de amenazas mediante Deep Learning
Características • Instalación • Uso • Arquitectura • Contribuir
</div>

📋 Descripción
SPYNET es un analizador de tráfico de red avanzado que combina técnicas tradicionales de inspección de paquetes con inteligencia artificial (Deep Learning) para detectar amenazas en tiempo real. Construido con Python, Tkinter, Scapy y TensorFlow, ofrece una interfaz gráfica intuitiva para monitorear, analizar y visualizar el tráfico de tu red.
### release: 
coming soon

## 🎯 Características Principales

### 🤖 Detección de Amenazas con IA

<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 132958" src="https://github.com/user-attachments/assets/f63e8283-8692-408e-9131-e7bb1de5b0c1" />


Modelo de Deep Learning con 78 características
Clasificación de ataques: DoS, DDoS, Port Scan, Botnet, Brute Force, Web Attacks
Análisis en tiempo real con hilo dedicado
Umbrales configurables para reducir falsos positivos


### 📊 Visualización en Tiempo Real

<img width="1917" height="1079" alt="Captura de pantalla 2025-12-07 133025" src="https://github.com/user-attachments/assets/d0a6552d-4075-4eb0-927d-ec8d6af8cdf7" />
<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 132748" src="https://github.com/user-attachments/assets/336af761-17e0-4f4a-9b8a-ec6791eebc75" />


Gráficos dinámicos de tráfico
Estadísticas de protocolos, países y puertos
Mapa de red con NetworkX
Dashboard exportable a PNG


### 🔍 Análisis Profundo de Paquetes

<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 132346" src="https://github.com/user-attachments/assets/ae9c9ea7-c4ca-4636-b1b4-632f4a5b1765" />
<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 132534" src="https://github.com/user-attachments/assets/fc303edb-a983-4195-8617-9bb17a8b4051" />

Inspección completa de TCP/UDP/ICMP/ARP
Detección de TCP Handshake (3-way)
Resolución DNS inversa
Geolocalización de IPs con MaxMind GeoIP


🛡️ Seguridad y Auditoría

<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 133119" src="https://github.com/user-attachments/assets/c16063b7-0cc8-4701-aff3-53e392ed3bb2" />
<img width="1919" height="1079" alt="Captura de pantalla 2025-12-07 132549" src="https://github.com/user-attachments/assets/29997901-db7e-43b2-a3dd-1d215ea968a5" />

Detección de puertos inseguros
Integración con VirusTotal API
Exportación de reportes a CSV
Captura y análisis de archivos PCAP

🖼️ Capturas de Pantalla
<div align="center">
Dashboard Principal
Mostrar imagen
Análisis de Tráfico
Mostrar imagen
Detección de IA
Mostrar imagen
Mapa de Red
Mostrar imagen
</div>

🚀 Instalación
Requisitos Previos

Python 3.8+
Privilegios de Administrador (requerido para captura de paquetes)
Windows/Linux/macOS compatible

Instalación Automática (Recomendada)
bash# 1. Clonar el repositorio
git clone https://github.com/ever186/spynet.git
cd spynet

# 2. Ejecutar como administrador
# Windows (CMD como Admin):
python main.py

# Linux/macOS:
sudo python3 main.py
El instalador automático verificará y descargará todas las dependencias necesarias.
Instalación Manual
bash# 1. Crear entorno virtual (opcional pero recomendado)
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Descargar base de datos GeoIP (opcional)
# Registrarse en https://www.maxmind.com/
# Descargar GeoLite2-City.mmdb y colocar en db/

# 4. Ejecutar
python main.py
```

### Dependencias Principales
```
scapy>=2.5.0
tensorflow>=2.12.0
keras>=2.12.0
pillow>=10.0.0
matplotlib>=3.7.0
networkx>=3.1
maxminddb>=2.2.0
requests>=2.31.0
joblib>=1.3.0
pandas>=2.0.0
numpy>=1.24.0

📖 Uso
Inicio Rápido

Ejecutar como Administrador (obligatorio para captura de paquetes)
Hacer clic en el botón ▶️ Iniciar Captura
Observar el tráfico en tiempo real en la pestaña "Análisis de Tráfico"
Ver detecciones de IA en la pestaña "Modelo AI"

Funcionalidades Principales
🔴 Captura de Tráfico
python# Botones de control:
▶️ Iniciar  - Comienza la captura
⏸️ Pausar   - Pausa temporalmente
⏹️ Detener  - Finaliza la captura
🗑️ Limpiar  - Borra datos actuales
🤖 Modelo de IA

Paquetes Analizados: Contador total de tráfico procesado
Sospechosos (Warning): Alertas de nivel medio
Críticos (Ataques): Amenazas confirmadas de alta confianza
Tabla de Detecciones: Log detallado con timestamp, tipo de ataque, IPs y confianza

📊 Visualización

Gráfico de Tráfico: KB/s en tiempo real
Protocolos: Distribución de TCP/UDP/HTTP/DNS/etc.
Países: Geolocalización de origen de tráfico
Puertos Inseguros: Detecta puertos de alto riesgo

🌐 Escaneo de Red
bash# En la pestaña "Dispositivos en Red":
1. Clic en 🔍 Buscar Dispositivos
2. Ver lista de hosts activos con IP, MAC y fabricante
3. Seleccionar un dispositivo → Escanear Puertos
💾 Importar/Exportar
bash# Exportar sesión actual
Archivo → Guardar Sesión de Captura... (.spynet)

# Cargar sesión previa
Archivo → Cargar Sesión de Captura...

# Exportar a CSV
Archivo → Exportar Vista Actual a CSV...

# Captura PCAP en vivo
Archivo → Activar Captura en .pcap ✓

# Analizar PCAP existente
Archivo → Importar Archivo .pcap...
🛡️ VirusTotal Integration
bash# Configurar API Key:
Opciones → Configurar API de VirusTotal...

# Analizar IP/Dominio:
Clic derecho en una fila → Analizar con VirusTotal

Flujo de Datos
mermaidgraph LR
    A[Captura de Paquetes<br/>Scapy] --> B[PacketHandler<br/>Procesar]
    B --> C[NetworkAnalyzer<br/>Controlador]
    C --> D[UI Thread<br/>Tabla/Gráficos]
    C --> E[AI Thread<br/>Cola Asíncrona]
    E --> F[AIAnomalyDetector<br/>78 Features]
    F --> G[Modelo TensorFlow<br/>Predicción]
    G --> H[AI_tab<br/>Alertas]

🧠 Modelo de Inteligencia Artificial
Características

Dataset: Entrenado con CIC-IDS2017
Arquitectura: Red Neuronal Profunda (DNN)
Features: 78 características estadísticas de flujo de red
Clases: Normal, DoS, DDoS, Port Scan, Botnet, Brute Force, Web Attack, Infiltration

Extracción de Características (78 Features)
<details>
<summary>Ver lista completa de features</summary>
````python
GRUPO 1: Estadísticas Básicas (13 features)
- Flow Duration
- Total Fwd/Bwd Packets
- Total Fwd/Bwd Packet Length
- Fwd/Bwd Packet Length Max/Min/Mean/Std
GRUPO 2: Flow Bytes/Packets per Second (4 features)

Flow Bytes/s
Flow Packets/s
Flow IAT Mean/Std

GRUPO 3: IAT Statistics (12 features)

Flow/Fwd/Bwd IAT Max/Min/Mean/Std

GRUPO 4: TCP Flags (16 features)

PSH/URG/FIN/SYN/RST/ACK/CWE/ECE Flag Count
Fwd/Bwd PSH/URG Flags
Fwd/Bwd Header Length

GRUPO 5: Flags Count (8 features)

FIN/SYN/RST/PSH/ACK/URG Flag Count

GRUPO 6: Características Adicionales (17 features)

Init Window Bytes Fwd/Bwd
Active/Idle Mean/Std/Max/Min

GRUPO 7: Protocol/Port Features (8 features)

Protocol Type
Source/Dest Port
TTL, ToS, DF/MF Flags


</details>

### Configuración de Umbrales (ia_config.py)
````python
CONFIDENCE_THRESHOLD = 0.60    # Umbral mínimo de confianza
CRITICAL_CONFIDENCE = 0.96     # Umbral para alertas críticas
CONFIDENCE_GAP_MIN = 0.05      # Gap mínimo entre predicciones

SAFE_PORTS = [80, 443, 53]     # Puertos seguros
SAFE_PORT_CONFIDENCE = 0.80    # Umbral para puertos seguros
Ajustar estos valores para:

⬆️ Valores más altos = Menos falsos positivos, más selectivo
⬇️ Valores más bajos = Más detecciones, más falsos positivos


⚙️ Configuración Avanzada
Personalizar Puertos Inseguros
python# En config.py:
INSECURE_PORTS_DEFAULT = {
    23,    # Telnet
    135,   # RPC
    139,   # NetBIOS
    445,   # SMB
    3389,  # RDP (si no es esperado)
    # Agregar más...
}
Configurar VirusTotal API

Registrarse en VirusTotal
Obtener API Key gratuita
En SPYNET: Opciones → Configurar API de VirusTotal

GeoIP Database
bash# 1. Registrarse en MaxMind (gratis)
https://www.maxmind.com/en/geolite2/signup

# 2. Descargar GeoLite2-City.mmdb
# 3. Colocar en: spynet/db/GeoLite2-City.mmdb

🐛 Solución de Problemas
Error: "Permission Denied" / "10013"
bash# ✅ Solución: Ejecutar como Administrador
# Windows:
Clic derecho en CMD → "Ejecutar como administrador"
python main.py

# Linux/macOS:
sudo python3 main.py
Error: "No module named 'scapy'"
bashpip install scapy
# o
pip install -r requirements.txt
La IA no detecta nada

````
Verificar que cicids2017_model.h5 y cicids2017_scaler.pkl existan en /model/
Revisar umbrales en ia_config.py (reducir CONFIDENCE_THRESHOLD)
Activar DEBUG_MODE = True en ia_config.py para ver logs

Pantalla en blanco al cargar PCAP grande
python# Usar "Modo Rápido" al importar PCAP
# Desmarca análisis de IA si el archivo tiene >100k paquetes

🤝 Contribuir
¡Las contribuciones son bienvenidas! Si encuentras un bug o tienes una idea:

Fork el proyecto
Crea tu rama de feature (git checkout -b feature/AmazingFeature)
Commit tus cambios (git commit -m 'Add some AmazingFeature')
Push a la rama (git push origin feature/AmazingFeature)
Abre un Pull Request

Reportar Bugs
Abre un Issue con:

Descripción del problema
Pasos para reproducir
Logs de error (si aplica)
Sistema operativo y versión de Python


📝 Roadmap

 Soporte para IPv6 completo
 Integración con más APIs de threat intelligence
 Exportar reportes a PDF
 Dashboard web (Flask/Django)
 Alertas por email/Telegram
 Entrenar modelo con datasets más recientes (CIC-IDS2018, CSE-CIC-IDS2018)
 Modo headless (CLI sin GUI)
 Docker containerization


📜 Licencia
Este proyecto está licenciado bajo la MIT License - ver el archivo LICENSE para más detalles.

👨‍💻 Autor
HackCat - GitHub
Si tienes preguntas o sugerencias, no dudes en contactar:

📧 Linkedln: https://www.linkedin.com/in/ever-junior-leiva-arias-371b06200/
🐙 GitHub Issues: Reportar un problema



🙏 Agradecimientos

Scapy - Framework de manipulación de paquetes
TensorFlow - Biblioteca de Deep Learning
CIC-IDS2017 - Dataset de entrenamiento
MaxMind GeoIP - Geolocalización de IPs
VirusTotal - API de análisis de amenazas


<div align="center">
⭐ Si este proyecto te fue útil, considera darle una estrella ⭐
Mostrar imagen
Mostrar imagen
Hecho con ❤️ por HackCat
</div>

⚠️ Disclaimer
Este software es solo para fines educativos y de investigación. El autor no se hace responsable del uso indebido de esta herramienta. Usar SPYNET para monitorear redes sin autorización es ilegal. Siempre obtén permiso explícito antes de analizar tráfico de red.
