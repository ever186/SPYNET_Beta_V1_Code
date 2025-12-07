# ==============================================================================
# utils/geoip_handler.py
# Clase para geolocalización (wrapper para MaxMindDB)
# ==============================================================================

import ipaddress
import os

class GeoIPHandler:
    """
    Gestiona la carga y consulta de la base de datos GeoLite2-City.mmdb.
    """
    
    def __init__(self, db_path):
        self.geoip_reader = None
        self.maxminddb = None
        
        try:
            import maxminddb
            self.maxminddb = maxminddb
        except ImportError:
            print("ADVERTENCIA: Módulo 'maxminddb' no encontrado. GeoIP desactivado.")
            return

        try:
            if not os.path.exists(db_path):
                raise FileNotFoundError
            self.geoip_reader = self.maxminddb.open_database(db_path)
            print(f"Base de datos GeoIP cargada desde {db_path}")
        except FileNotFoundError:
            print(f"ADVERTENCIA: Archivo {db_path} no encontrado. La geolocalización estará desactivada.")
        except Exception as e:
            print(f"Error al cargar la base de datos GeoIP: {e}")

    def get_country_code(self, ip):
        """
        Devuelve el código de país (ISO) para una IP.
        """
        if not self.geoip_reader or ipaddress.ip_address(ip).is_private:
            return "Local/Privada"
        
        try:
            record = self.geoip_reader.get(ip)
            if record and 'country' in record and 'iso_code' in record['country']:
                return record['country']['iso_code']
            return "N/A"
        except Exception:
            return "Error"