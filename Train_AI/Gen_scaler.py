#==============================================================================
# Script para generar el scaler_full.pkl desde tu dataset original
# Usa EXACTAMENTE el mismo proceso que usaste al entrenar
#==============================================================================

import kagglehub
import os
import pandas as pd
import glob
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

print("[+] Descargando dataset...")
dataset_path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")

print("[+] Cargando archivos CSV...")
csv_files = glob.glob(os.path.join(dataset_path, "*.csv"))

dfs = []
for f in csv_files:
    print("[+] Leyendo:", os.path.basename(f))
    df_temp = pd.read_csv(f, low_memory=False)
    dfs.append(df_temp)

df = pd.concat(dfs, ignore_index=True)
print("[+] Dataset total:", df.shape)

# --- Limpieza EXACTA (como en tu entrenamiento) ---
print("[+] Limpiando datos...")
df.columns = df.columns.str.strip()

# Eliminar columna 'label' si existe
if "label" in df.columns:
    df.drop(columns=["label"], inplace=True)

if "Label" not in df.columns:
    raise ValueError("ERROR: No se encontró la columna 'Label'")

# Reemplazar infinitos
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Eliminar filas con valores NaN
df.dropna(inplace=True)

# Separar features y label
y = df["Label"]
X = df.drop(columns=["Label"])

# Convertir características categóricas a números
cat_cols = X.select_dtypes(include=["object"]).columns
if len(cat_cols) > 0:
    print("[+] Codificando columnas categóricas:", list(cat_cols))
    X = pd.get_dummies(X, columns=cat_cols)

print(f"[+] Número total de características: {X.shape[1]}")
print(f"[+] Nombres de las columnas:\n{list(X.columns)}")

# CREAR Y ENTRENAR EL SCALER
print("[+] Creando StandardScaler...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# GUARDAR EL SCALER
output_path = "scaler_full.pkl"
joblib.dump(scaler, output_path)

print(f"[✓] Scaler guardado como: {output_path}")
print(f"[✓] Dimensiones: {X.shape[1]} características")
print(f"\n[!] IMPORTANTE:")
print(f"    1. Copia 'scaler_full.pkl' a tu carpeta 'models/'")
print(f"    2. El modelo espera {X.shape[1]} características")
print(f"    3. Guarda esta lista de columnas para el siguiente paso")

# Guardar lista de columnas para referencia
with open("feature_names.txt", "w") as f:
    for col in X.columns:
        f.write(f"{col}\n")

print(f"[✓] Lista de características guardada en: feature_names.txt")