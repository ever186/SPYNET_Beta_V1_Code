# ==============================================================================
# core/anomaly_detector.py
# Detector con EXACTAMENTE 78 características
# ==============================================================================
import os
import numpy as np
import joblib
from collections import defaultdict
import time
import warnings

# Suprimir warnings de feature names (no afecta la funcionalidad)
warnings.filterwarnings('ignore', message='X does not have valid feature names')

# Importar configuración de umbrales
try:
    from ia_config import IAConfig
except ImportError:
    # Si no existe el archivo, usar valores por defecto
    class IAConfig:
        CONFIDENCE_THRESHOLD = 0.85
        CRITICAL_CONFIDENCE = 0.96
        CONFIDENCE_GAP_MIN = 0.15
        SAFE_PORTS = [80, 443, 53, 123, 22]
        SAFE_HOSTS = ["13.107.", "20.", "40.", "52."]
        SAFE_PORT_CONFIDENCE = 0.95
        PRIVATE_NETWORK_CONFIDENCE = 0.92
        PRIVATE_IP_PREFIXES = ['192.168.', '10.', '172.16.', '127.']
        CRITICAL_ATTACK_KEYWORDS = ["DoS", "DDoS", "Botnet", "Infiltration", "Brute Force", "Exploit"]
        DEBUG_MODE = False

try:
    from keras.models import load_model
    TF_AVAILABLE = True
except:
    TF_AVAILABLE = False
    print("[!] TensorFlow/Keras no disponible. IA desactivada.")

from config import IA_MODEL_PATH, IA_SCALER_PATH

class AIAnomalyDetector:
    
    N_FEATURES = 78  # FIJO: Tu modelo espera 78
    
    # AJUSTA ESTOS LABELS según tu dataset
    # Para ver tus clases reales, revisa la salida de tu entrenamiento
    CLASS_LABELS = {
        0: "Normal",
        1: "DoS Attack",
        2: "DDoS",
        3: "Port Scan",
        4: "Botnet",
        5: "Brute Force",
        6: "Web Attack",
        7: "Infiltration"
        # Añade más si tu modelo tiene más clases
    }

    def __init__(self, model_path=IA_MODEL_PATH, scaler_path=IA_SCALER_PATH):
        self.model = None
        self.scaler = None
        
        # Estadísticas de flujo
        self.flow_stats = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'bytes_total': 0,
            'packet_count': 0,
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'urg_count': 0
        })
        
        if TF_AVAILABLE and os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = load_model(model_path)
                self.scaler = joblib.load(scaler_path)
                print(f"[✓] Modelo IA cargado: {model_path}")
                print(f"[✓] Scaler cargado: {scaler_path}")
                print(f"[✓] Características esperadas: {self.N_FEATURES}")
            except Exception as e:
                print(f"[!] Error cargando modelo: {e}")
                self.model = None
        else:
            if not TF_AVAILABLE:
                print("[!] TensorFlow no disponible")
            elif not os.path.exists(model_path):
                print(f"[!] Modelo no encontrado: {model_path}")
            elif not os.path.exists(scaler_path):
                print(f"[!] Scaler no encontrado: {scaler_path}")

    def _get_flow_key(self, packet):
        """Genera clave única para identificar el flujo"""
        try:
            if packet.haslayer('IP'):
                ip = packet['IP']
                proto = ip.proto
                
                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                elif packet.haslayer('UDP'):
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                else:
                    src_port = 0
                    dst_port = 0
                
                key = tuple(sorted([
                    (ip.src, src_port),
                    (ip.dst, dst_port)
                ]) + [proto])
                
                return key
        except:
            pass
        return None

    def _extract_features_78(self, packet):
        """
        Extrae EXACTAMENTE 78 características del paquete.
        Basado en el dataset CIC-IDS2017/CSE-CIC-IDS2018.
        """
        features = np.zeros(self.N_FEATURES, dtype=np.float32)
        
        try:
            timestamp = time.time()
            flow_key = self._get_flow_key(packet)
            packet_len = len(packet)
            
            # Actualizar estadísticas del flujo
            if flow_key:
                flow = self.flow_stats[flow_key]
                flow['packets'].append(packet_len)
                flow['timestamps'].append(timestamp)
                flow['bytes_total'] += packet_len
                flow['packet_count'] += 1
                
                # Limpiar datos antiguos (>60 segundos)
                cutoff = timestamp - 60
                while flow['timestamps'] and flow['timestamps'][0] < cutoff:
                    flow['timestamps'].pop(0)
                    flow['packets'].pop(0)
            
            idx = 0
            
            # ========== GRUPO 1: Estadísticas Básicas (0-12) ==========
            
            # 0. Duración del flujo
            if flow_key and len(flow['timestamps']) > 1:
                features[idx] = flow['timestamps'][-1] - flow['timestamps'][0]
            idx += 1
            
            # 1-2. Total de paquetes forward/backward
            if flow_key:
                features[idx] = flow['packet_count']  # Forward
                idx += 1
                features[idx] = 0  # Backward (aproximado)
                idx += 1
            else:
                idx += 2
            
            # 3-5. Longitud total de bytes (forward/backward/total)
            if flow_key:
                features[idx] = flow['bytes_total']  # Forward
                idx += 1
                features[idx] = 0  # Backward
                idx += 1
                features[idx] = flow['bytes_total']  # Total
                idx += 1
            else:
                features[idx] = packet_len
                idx += 1
                features[idx] = 0
                idx += 1
                features[idx] = packet_len
                idx += 1
            
            # 6-9. Longitud máxima/mínima de paquetes forward
            if flow_key and flow['packets']:
                features[idx] = max(flow['packets'])  # Max
                idx += 1
                features[idx] = min(flow['packets'])  # Min
                idx += 1
                features[idx] = np.mean(flow['packets'])  # Mean
                idx += 1
                features[idx] = np.std(flow['packets']) if len(flow['packets']) > 1 else 0  # Std
                idx += 1
            else:
                features[idx:idx+4] = [packet_len, packet_len, packet_len, 0]
                idx += 4
            
            # 10-12. Longitud backward (aproximado)
            features[idx:idx+3] = 0
            idx += 3
            
            # ========== GRUPO 2: Flow Bytes/Packets per Second (13-16) ==========
            
            if flow_key and len(flow['timestamps']) > 1:
                duration = flow['timestamps'][-1] - flow['timestamps'][0]
                if duration > 0:
                    features[idx] = flow['bytes_total'] / duration  # Flow Bytes/s
                    idx += 1
                    features[idx] = flow['packet_count'] / duration  # Flow Packets/s
                    idx += 1
                    features[idx] = features[idx-2] / 2  # Flow IAT Mean (aproximado)
                    idx += 1
                    features[idx] = 0  # Flow IAT Std
                    idx += 1
                else:
                    idx += 4
            else:
                idx += 4
            
            # ========== GRUPO 3: IAT Statistics (17-28) ==========
            
            if flow_key and len(flow['timestamps']) > 1:
                iats = np.diff(flow['timestamps'])
                
                # 17-21. Flow IAT
                features[idx] = np.max(iats) if len(iats) > 0 else 0  # IAT Max
                idx += 1
                features[idx] = np.min(iats) if len(iats) > 0 else 0  # IAT Min
                idx += 1
                features[idx] = np.mean(iats) if len(iats) > 0 else 0  # IAT Mean
                idx += 1
                features[idx] = np.std(iats) if len(iats) > 1 else 0  # IAT Std
                idx += 1
                features[idx] = iats[-1] if len(iats) > 0 else 0  # IAT Total
                idx += 1
                
                # 22-27. Forward/Backward IAT (aproximado)
                features[idx:idx+6] = features[idx-5:idx-5+6] / 2
                idx += 6
            else:
                idx += 12
            
            # 28. Active/Idle statistics (simplificado)
            features[idx] = 1 if flow_key and flow['packet_count'] > 5 else 0
            idx += 1
            
            # ========== GRUPO 4: FLAGS TCP (29-44) ==========
            
            if packet.haslayer('TCP'):
                tcp = packet['TCP']
                flags = tcp.flags
                
                if flow_key:
                    flow['syn_count'] += 1 if flags.S else 0
                    flow['ack_count'] += 1 if flags.A else 0
                    flow['fin_count'] += 1 if flags.F else 0
                    flow['rst_count'] += 1 if flags.R else 0
                    flow['psh_count'] += 1 if flags.P else 0
                    flow['urg_count'] += 1 if flags.U else 0
                
                # 29-30. PSH Flags
                features[idx] = 1 if flags.P else 0  # Fwd PSH
                idx += 1
                features[idx] = 0  # Bwd PSH
                idx += 1
                
                # 31-32. URG Flags
                features[idx] = 1 if flags.U else 0  # Fwd URG
                idx += 1
                features[idx] = 0  # Bwd URG
                idx += 1
                
                # 33-34. Header Length
                features[idx] = tcp.dataofs * 4  # TCP header length
                idx += 1
                features[idx] = 0  # Backward
                idx += 1
                
                # 35-36. Packets/s forward/backward
                if flow_key and len(flow['timestamps']) > 1:
                    duration = flow['timestamps'][-1] - flow['timestamps'][0]
                    if duration > 0:
                        features[idx] = flow['packet_count'] / duration
                        idx += 1
                        features[idx] = 0
                        idx += 1
                    else:
                        idx += 2
                else:
                    idx += 2
                
                # 37-44. Down/Up Ratio, Avg Packet Size, etc.
                features[idx] = 0  # Down/Up Ratio
                idx += 1
                if flow_key and flow['packets']:
                    features[idx] = np.mean(flow['packets'])  # Avg Segment Size
                    idx += 1
                else:
                    features[idx] = packet_len
                    idx += 1
                
                features[idx] = 0  # Avg Bwd Segment Size
                idx += 1
                
                # 40-44. Subflow stats (simplificado)
                features[idx:idx+5] = 0
                idx += 5
                
            else:
                # No es TCP, llenar con ceros
                idx += 16
            
            # ========== GRUPO 5: Flags Count (45-52) ==========
            
            if packet.haslayer('TCP') and flow_key:
                flow = self.flow_stats[flow_key]
                features[idx] = flow['fin_count']  # FIN
                idx += 1
                features[idx] = flow['syn_count']  # SYN
                idx += 1
                features[idx] = flow['rst_count']  # RST
                idx += 1
                features[idx] = flow['psh_count']  # PSH
                idx += 1
                features[idx] = flow['ack_count']  # ACK
                idx += 1
                features[idx] = flow['urg_count']  # URG
                idx += 1
                features[idx] = 0  # CWE (ECN)
                idx += 1
                features[idx] = 0  # ECE (ECN)
                idx += 1
            else:
                idx += 8
            
            # ========== GRUPO 6: Características Adicionales (53-69) ==========
            
            # 53-55. Init Window bytes
            if packet.haslayer('TCP'):
                features[idx] = packet['TCP'].window
                idx += 1
                features[idx] = 0  # Backward
                idx += 1
            else:
                idx += 2
            
            # 56. Act Data Pkt Fwd
            features[idx] = 1 if packet.haslayer('TCP') and len(packet['TCP'].payload) > 0 else 0
            idx += 1
            
            # 57-58. Min Segment Size
            if flow_key and flow['packets']:
                features[idx] = min(flow['packets'])
                idx += 1
            else:
                features[idx] = packet_len
                idx += 1
            features[idx] = 0  # Backward
            idx += 1
            
            # 59-69. Active/Idle statistics (11 features)
            if flow_key and len(flow['timestamps']) > 2:
                # Calcular períodos activos vs idle
                iats = np.diff(flow['timestamps'])
                active_periods = [iat for iat in iats if iat < 1.0]  # < 1 segundo = activo
                idle_periods = [iat for iat in iats if iat >= 1.0]
                
                if active_periods:
                    features[idx] = np.mean(active_periods)  # Active Mean
                    idx += 1
                    features[idx] = np.std(active_periods) if len(active_periods) > 1 else 0
                    idx += 1
                    features[idx] = np.max(active_periods)
                    idx += 1
                    features[idx] = np.min(active_periods)
                    idx += 1
                else:
                    idx += 4
                
                if idle_periods:
                    features[idx] = np.mean(idle_periods)  # Idle Mean
                    idx += 1
                    features[idx] = np.std(idle_periods) if len(idle_periods) > 1 else 0
                    idx += 1
                    features[idx] = np.max(idle_periods)
                    idx += 1
                    features[idx] = np.min(idle_periods)
                    idx += 1
                else:
                    idx += 4
                
                # Resto de features activas/idle
                features[idx:idx+3] = 0
                idx += 3
            else:
                idx += 11
            
            # ========== GRUPO 7: Protocol/Port Features (70-77) ==========
            
            # 70. Protocol
            if packet.haslayer('IP'):
                features[idx] = packet['IP'].proto
                idx += 1
            else:
                idx += 1
            
            # 71-72. Source/Dest Port
            if packet.haslayer('TCP'):
                features[idx] = packet['TCP'].sport
                idx += 1
                features[idx] = packet['TCP'].dport
                idx += 1
            elif packet.haslayer('UDP'):
                features[idx] = packet['UDP'].sport
                idx += 1
                features[idx] = packet['UDP'].dport
                idx += 1
            else:
                idx += 2
            
            # 73-77. Características finales
            if packet.haslayer('IP'):
                features[idx] = packet['IP'].ttl  # TTL
                idx += 1
                features[idx] = packet['IP'].tos  # Type of Service
                idx += 1
            else:
                idx += 2
            
            # Flags adicionales
            if packet.haslayer('IP'):
                features[idx] = 1 if packet['IP'].flags.DF else 0  # Don't Fragment
                idx += 1
                features[idx] = 1 if packet['IP'].flags.MF else 0  # More Fragments
                idx += 1
            else:
                idx += 2
            
            # Padding final si es necesario
            features[idx] = packet_len % 256  # Tamaño mod 256
            idx += 1
            
            # Asegurar que siempre sean 78
            if idx < self.N_FEATURES:
                features[idx:] = 0
            
            return features[:self.N_FEATURES]
            
        except Exception as e:
            print(f"[!] Error extrayendo features: {e}")
            return np.zeros(self.N_FEATURES, dtype=np.float32)

    def analyze_packet_struct(self, packet):
        """
        Analiza un paquete y retorna detección de anomalía.
        AHORA RETORNA TAMBIÉN TRÁFICO NORMAL PARA CONTEO.
        """
        # =======================================================
        # 1. Extracción segura de IP Destino
        # =======================================================
        if packet.haslayer('IP'):
            dst_ip = packet['IP'].dst
        else:
            dst_ip = None
            
        if dst_ip and any(dst_ip.startswith(prefix) for prefix in IAConfig.SAFE_HOSTS):
            # CAMBIO: En vez de retornar None, retornamos info de tráfico normal
            return {
                'label': 'Normal',
                'conf': 0.0,
                'src': packet['IP'].src if packet.haslayer('IP') else "-",
                'dst': dst_ip,
                'severity': 'normal',
                'skip_alert': True  # Nueva bandera para no mostrar en tabla
            }

        if self.model is None:
            return None

        try:
            # Extraer 78 características
            features = self._extract_features_78(packet)
            
            # Convertir a DataFrame
            import pandas as pd
            try:
                feature_names = self.scaler.feature_names_in_
                features_df = pd.DataFrame([features], columns=feature_names)
                scaled = self.scaler.transform(features_df)
            except AttributeError:
                scaled = self.scaler.transform([features])
            
            # =======================================================
            # 2. Predicción de la IA
            # =======================================================
            prediction = self.model.predict(scaled, verbose=0)[0]
            
            idx = np.argmax(prediction)
            label = self.CLASS_LABELS.get(idx, f"Clase_{idx}")
            confidence = float(prediction[idx])

            # =======================================================
            # 3. Filtros Post-Predicción
            # =======================================================

            # Filtro de TTL
            if packet.haslayer('IP'):
                if packet['IP'].ttl >= 100 and confidence < 0.97:
                    # CAMBIO: Retornar como normal en vez de None
                    return {
                        'label': 'Normal',
                        'conf': confidence,
                        'src': packet['IP'].src,
                        'dst': dst_ip if dst_ip else packet['IP'].dst,
                        'severity': 'normal',
                        'skip_alert': True
                    }

            # 1. Si es tráfico normal, reportar pero no alertar
            if label == "Normal" or "BENIGN" in label.upper():
                return {
                    'label': 'Normal',
                    'conf': confidence,
                    'src': packet['IP'].src if packet.haslayer('IP') else "-",
                    'dst': dst_ip if dst_ip else "-",
                    'severity': 'normal',
                    'skip_alert': True  # No mostrar en tabla de alertas
                }
            
            # 2. Umbral de confianza
            if confidence < IAConfig.CONFIDENCE_THRESHOLD:
                if IAConfig.DEBUG_MODE:
                    print(f"[IA] Descartado por baja confianza: {label} ({confidence:.2f})")
                # CAMBIO: Reportar como normal
                return {
                    'label': 'Normal',
                    'conf': confidence,
                    'src': packet['IP'].src if packet.haslayer('IP') else "-",
                    'dst': dst_ip if dst_ip else "-",
                    'severity': 'normal',
                    'skip_alert': True
                }
            
            # 3. Verificar ambigüedad
            sorted_probs = np.sort(prediction)[::-1]
            if len(sorted_probs) > 1:
                confidence_gap = sorted_probs[0] - sorted_probs[1]
                if confidence_gap < IAConfig.CONFIDENCE_GAP_MIN:
                    if IAConfig.DEBUG_MODE:
                        print(f"[IA] Descartado por ambigüedad: {label} (gap: {confidence_gap:.2f})")
                    return {
                        'label': 'Normal',
                        'conf': confidence,
                        'src': packet['IP'].src if packet.haslayer('IP') else "-",
                        'dst': dst_ip if dst_ip else "-",
                        'severity': 'normal',
                        'skip_alert': True
                    }
            
            # 4. Filtrar puertos seguros
            if packet.haslayer('TCP') or packet.haslayer('UDP'):
                port = None
                if packet.haslayer('TCP'):
                    port = packet['TCP'].dport
                elif packet.haslayer('UDP'):
                    port = packet['UDP'].dport
                
                if port in IAConfig.SAFE_PORTS and confidence < IAConfig.SAFE_PORT_CONFIDENCE:
                    if IAConfig.DEBUG_MODE:
                        print(f"[IA] Descartado por puerto seguro: {port}")
                    return {
                        'label': 'Normal',
                        'conf': confidence,
                        'src': packet['IP'].src if packet.haslayer('IP') else "-",
                        'dst': dst_ip if dst_ip else "-",
                        'severity': 'normal',
                        'skip_alert': True
                    }
            
            # 5. Filtrar tráfico privado
            if dst_ip:
                is_private = any(dst_ip.startswith(prefix) for prefix in IAConfig.PRIVATE_IP_PREFIXES)
                if is_private and confidence < IAConfig.PRIVATE_NETWORK_CONFIDENCE:
                    if IAConfig.DEBUG_MODE:
                        print(f"[IA] Descartado por IP privada: {dst_ip}")
                    return {
                        'label': 'Normal',
                        'conf': confidence,
                        'src': packet['IP'].src if packet.haslayer('IP') else "-",
                        'dst': dst_ip,
                        'severity': 'normal',
                        'skip_alert': True
                    }

            # Determinar severidad para AMENAZAS REALES
            severity = 'suspicious'
            
            if any(keyword.lower() in label.lower() for keyword in IAConfig.CRITICAL_ATTACK_KEYWORDS):
                severity = 'critical'
            
            # Reducir falsos positivos de botnets
            if label == "Botnet":
                flow = self.flow_stats.get(self._get_flow_key(packet), None)
                if flow and flow['packet_count'] < 20:
                    return {
                        'label': 'Normal',
                        'conf': confidence,
                        'src': packet['IP'].src if packet.haslayer('IP') else "-",
                        'dst': dst_ip if dst_ip else "-",
                        'severity': 'normal',
                        'skip_alert': True
                    }
                
            if confidence > IAConfig.CRITICAL_CONFIDENCE:
                severity = 'critical'

            # Extraer IPs
            src = packet['IP'].src if packet.haslayer('IP') else "-"
            dst = dst_ip if dst_ip else "-"

            # AMENAZA DETECTADA (sí mostrar en tabla)
            return {
                'label': label,
                'conf': confidence,
                'src': src,
                'dst': dst,
                'severity': severity,
                'skip_alert': False  # SÍ mostrar en tabla de alertas
            }
            
        except Exception as e:
            return None
         
    def cleanup_old_flows(self):
        """Limpia flujos antiguos para evitar fugas de memoria"""
        current_time = time.time()
        cutoff = current_time - 300  # 5 minutos
        
        keys_to_delete = [
            key for key, flow in self.flow_stats.items()
            if flow['timestamps'] and flow['timestamps'][-1] < cutoff
        ]
        
        for key in keys_to_delete:
            del self.flow_stats[key]
        
        if keys_to_delete:
            print(f"[IA] Limpiados {len(keys_to_delete)} flujos antiguos")