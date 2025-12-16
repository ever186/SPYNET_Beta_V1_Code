# ==============================================================================
# ia_config.py
# Configuración de umbrales para el detector de anomalías
# ==============================================================================

class IAConfig:
    """
    Configuración de umbrales para reducir/aumentar sensibilidad del detector
    """
    
    # ========== UMBRALES DE CONFIANZA ==========
    
    # Umbral mínimo de confianza para considerar una alerta
    # Valores más altos = menos falsos positivos, menos detecciones
    # Valores más bajos = más detecciones, más falsos positivos
    CONFIDENCE_THRESHOLD = 0.60 
    
    # Umbral para marcar como CRÍTICO
    CRITICAL_CONFIDENCE = 0.96   # Recomendado: 0.95-0.98
    
    # Diferencia mínima entre la predicción más alta y la segunda
    # Evita alertas cuando el modelo está "indeciso"
    CONFIDENCE_GAP_MIN = 0.05

    # ========== FILTROS DE PUERTOS ==========
    
    # Puertos y hots comunes que rara vez son ataques
    # Solo se alertan si la confianza es MUY alta
    SAFE_PORTS = [
        80,    # HTTP
        443,   # HTTPS
        53,    # DNS
        123,   # NTP
        22,    # SSH (legítimo)
        21,    # FTP (legítimo)
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        3389,  # RDP (legítimo)
    ]
    
    # IPs seguras a considerar (LISTA BLANCA)

    SAFE_HOSTS = [
        "13.107.0.0/16",  # Usar CIDR notation
        "20.0.0.0/8"
    ]
    
    # Umbral de confianza para puertos seguros
    SAFE_PORT_CONFIDENCE = 0.80
    
    # ========== FILTROS DE RED ==========
    
    # Umbral para tráfico en redes privadas
    PRIVATE_NETWORK_CONFIDENCE = 0.70
    
    # IPs privadas a considerar
    PRIVATE_IP_PREFIXES = [
        '192.168.',  # Clase C privada
        '10.',       # Clase A privada
        '172.16.',   # Clase B privada (inicio)
        '172.31.',   # Clase B privada (fin)
        '127.',      # Loopback
    ]
    
    # ========== PALABRAS CLAVE CRÍTICAS ==========
    
    # Tipos de ataque que siempre se marcan como críticos
    CRITICAL_ATTACK_KEYWORDS = [
        "DoS",
        "DDoS",
        "Botnet",
        "Bot",
        "Infiltration",
        "Brute Force",
        "Exploit",
        "Backdoor",
        "Ransomware",
        "Trojan"
    ]
    
    # ========== LÍMITES DE PROCESAMIENTO ==========
    
    # Tamaño máximo de la cola de análisis
    QUEUE_MAX_SIZE = 2000  # Aumentado para evitar pérdida de paquetes
    
    # Cada cuántos paquetes limpiar memoria
    CLEANUP_INTERVAL = 1000
    
    # Cada cuántos paquetes actualizar contador en UI
    UI_UPDATE_INTERVAL = 50
    
    # Tiempo máximo para retener estadísticas de flujo (segundos)
    FLOW_RETENTION_TIME = 300  # 5 minutos
    
    # ========== DEBUG Y LOGGING ==========
    
    # Mostrar estadísticas cada X paquetes procesados
    STATS_INTERVAL = 1000
    
    # Modo debug (más información en consola)
    DEBUG_MODE = True


# Función helper para verificar configuración
def validate_config():
    """Valida que los umbrales sean coherentes"""
    issues = []
    
    if IAConfig.CONFIDENCE_THRESHOLD >= IAConfig.CRITICAL_CONFIDENCE:
        issues.append("⚠️  CONFIDENCE_THRESHOLD debe ser menor que CRITICAL_CONFIDENCE")
    
    if IAConfig.CONFIDENCE_THRESHOLD < 0.5:
        issues.append("⚠️  CONFIDENCE_THRESHOLD muy bajo (<0.5), habrá muchos falsos positivos")
    
    if IAConfig.CONFIDENCE_THRESHOLD > 0.95:
        issues.append("⚠️  CONFIDENCE_THRESHOLD muy alto (>0.95), se perderán muchas detecciones")
    
    if issues:
        print("\n" + "="*60)
        print("ADVERTENCIAS DE CONFIGURACIÓN:")
        for issue in issues:
            print(f"  {issue}")
        print("="*60 + "\n")
    else:
        print("[✓] Configuración de IA validada correctamente")

# Ejecutar validación al importar
if __name__ == "__main__":

    validate_config()
