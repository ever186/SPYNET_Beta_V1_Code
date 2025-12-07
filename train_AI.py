# ======================================================================
# train_spynet_ai.py
# ENTRENAMIENTO PROFESIONAL SPYNET NIDS usando CICIDS2017
#
# - Carga CICIDS2017 con nids_datasets.load_pandas()
# - Adaptación de columnas de flujo -> 20 features SPYNET en tiempo real
# - Entrenamiento Deep CNN (Conv1D)
# - Salida: spynet_nids_model.h5 y spynet_scaler.pkl
#
# ======================================================================

import numpy as np
import pandas as pd
import joblib
import sys
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from keras.models import Sequential
from keras.layers import (
    Conv1D, MaxPooling1D, Flatten,
    Dense, Dropout, BatchNormalization
)
from keras.utils import to_categorical
from keras.callbacks import EarlyStopping

# -----------------------------------------------------------
# IMPORTAR DATASET
# -----------------------------------------------------------
try:
    from nids_datasets import Dataset
except ImportError:
    print("ERROR: Instala la librería:")
    print("      pip install nids-datasets")
    sys.exit(1)

# -----------------------------------------------------------
# CONFIGURACIONES
# -----------------------------------------------------------
MODEL_PATH = "spynet_nids_model.h5"
SCALER_PATH = "spynet_scaler.pkl"
N_FEATURES = 20
N_CLASSES = 4

LABEL_MAPPING = {
    'BENIGN': 0,
    'DoS Hulk': 1,
    'DoS GoldenEye': 1,
    'DoS slowloris': 1,
    'DoS Slowhttptest': 1,
    'DDoS': 1,
    'PortScan': 2,
    'FTP-Patator': 2,
    'SSH-Patator': 2,
    'Infiltration': 2,
    'Bot': 2,
    'Web Attack  Brute Force': 2,
    'Web Attack  XSS': 2,
    'Web Attack  Sql Injection': 2
}


# -----------------------------------------------------------
#   ADAPTAR CICIDS2017 A FEATURES SPYNET (20 Features)
# -----------------------------------------------------------
def adapt_cicids_to_spynet(df):

    print("[ETL] Adaptando dataset CICIDS2017 → SPYNET...")

    new = pd.DataFrame()

    # 1. Tamaño (Mean)
    new['size'] = df['Fwd Packet Length Mean']

    # 2. TTL (no existe en CICIDS → valor estándar)
    new['ttl'] = 64

    # 3. IP Flags
    new['ip_df'] = 1
    new['ip_mf'] = 0

    # 4. Protocolo
    new['is_tcp'] = (df['Protocol'] == 6).astype(int)

    # 5. Puertos
    new['tcp_sport'] = df['Source Port']
    new['tcp_dport'] = df['Destination Port']

    # 6. TCP Flags
    new['tcp_syn'] = df['SYN Flag Count']
    new['tcp_ack'] = df['ACK Flag Count']
    new['tcp_fin'] = df['FIN Flag Count']
    new['tcp_rst'] = df['RST Flag Count']
    new['tcp_psh'] = df['PSH Flag Count']
    new['tcp_urg'] = df['URG Flag Count']

    # 7. UDP
    new['is_udp'] = (df['Protocol'] == 17).astype(int)
    new['udp_sport'] = np.where(new['is_udp'] == 1, df['Source Port'], 0)
    new['udp_dport'] = np.where(new['is_udp'] == 1, df['Destination Port'], 0)

    # 8. ICMP
    new['is_icmp'] = (df['Protocol'] == 1).astype(int)
    new['icmp_type'] = 0
    new['icmp_code'] = 0

    # 9. DNS
    new['is_dns'] = (
        (df['Destination Port'] == 53) |
        (df['Source Port'] == 53)
    ).astype(int)

    # 10. Etiquetas
    def map_label(lbl):
        return LABEL_MAPPING.get(lbl, 2 if lbl != "BENIGN" else 0)

    new['Label'] = df['Label'].apply(map_label)

    # Ataques DNS
    dns_mask = (new['Label'] != 0) & (new['is_dns'] == 1)
    new.loc[dns_mask, 'Label'] = 3

    new = new.fillna(0)
    return new


# -----------------------------------------------------------
#   DEEP CNN
# -----------------------------------------------------------
def build_deep_model(input_shape, num_classes):
    model = Sequential()

    # Bloque Conv1
    model.add(Conv1D(64, 3, activation='relu', padding='same', input_shape=input_shape))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(2))

    # Bloque Conv2
    model.add(Conv1D(128, 3, activation='relu', padding='same'))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(2))

    # Dense
    model.add(Flatten())
    model.add(Dense(512, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dropout(0.5))

    model.add(Dense(256, activation='relu'))
    model.add(Dropout(0.4))

    model.add(Dense(128, activation='relu'))
    model.add(Dropout(0.3))

    model.add(Dense(num_classes, activation='softmax'))

    model.compile(
        optimizer='adam',
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )

    return model


# -----------------------------------------------------------
#   MAIN
# -----------------------------------------------------------
def main():

    print("=" * 70)
    print("   ENTRENADOR SPYNET NIDS - CICIDS2017 (Deep CNN)")
    print("=" * 70)

    print("[DATA] Cargando dataset CICIDS2017 completo...")

    ds = Dataset("CICIDS2017")

    try:
        df_raw = ds.load_pandas()
    except Exception as e:
        print(f"[ERROR] No pude cargar el dataset: {e}")
        sys.exit(1)

    # Para no saturar memoria
    df_raw = df_raw.sample(frac=0.2, random_state=42)
    print(f"[DATA] Filas cargadas: {len(df_raw)}")

    # ETL
    df = adapt_cicids_to_spynet(df_raw)

    print("[DATA] Distribución de clases:")
    print(df['Label'].value_counts())

    # Separar X / y
    X = df.drop(columns=['Label']).values
    y = df['Label'].values

    y_cat = to_categorical(y, num_classes=N_CLASSES)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_cat,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # Escalado
    print("[PREPROC] Escalando datos...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Reshape CNN
    X_train = X_train.reshape((X_train.shape[0], N_FEATURES, 1))
    X_test = X_test.reshape((X_test.shape[0], N_FEATURES, 1))

    # Modelo
    print("[IA] Construyendo modelo CNN...")
    model = build_deep_model((N_FEATURES, 1), N_CLASSES)

    early = EarlyStopping(monitor="val_accuracy", patience=3, restore_best_weights=True)

    print("[IA] Entrenando modelo...")
    model.fit(
        X_train, y_train,
        epochs=10,
        batch_size=128,
        validation_data=(X_test, y_test),
        callbacks=[early],
        verbose=1
    )

    # Evaluación
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"[RESULTADO] Precisión Final: {acc * 100:.2f}%")

    # Guardar
    model.save(MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print("=" * 70)
    print(" ENTRENAMIENTO COMPLETO ")
    print(f" Modelo guardado en: {MODEL_PATH}")
    print(f" Scaler guardado en: {SCALER_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    main()
