#==============================================================================
# Normalizacion de datos
#==============================================================================

import kagglehub
import os
import pandas as pd
import glob
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

print("[+] Descargando dataset...")
dataset_path = kagglehub.dataset_download("chethuhn/network-intrusion-dataset")

print("[+] Cargando archivos CSV...")
csv_files = glob.glob(os.path.join(dataset_path, "*.csv"))

dfs = []
for f in csv_files:
    print("[+] Leyendo:", os.path.basename(f))
    df_temp = pd.read_csv(f, low_memory=False)
    dfs.append(df_temp)

# Unimos todo el dataset
df = pd.concat(dfs, ignore_index=True)
print("[+] Dataset total:", df.shape)

# --- Limpieza ---
print("[+] Limpiando datos...")
df.columns = df.columns.str.strip()   # <--- ESTA LÍNEA ES LA CLAVE

# Eliminar columna 'label' que no sirve
if "label" in df.columns:
    df.drop(columns=["label"], inplace=True)

if "Label" not in df.columns:
    raise ValueError("ERROR: No se encontró la columna 'Label' incluso después de limpiar los nombres.")
# Reemplazar infinitos
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Eliminar filas con valores NaN
df.dropna(inplace=True)

# La etiqueta correcta es 'Label'
y = df["Label"]

# Eliminamos la columna 'Label' del dataset de características
X = df.drop(columns=["Label"])

# Convertir características categóricas a números
cat_cols = X.select_dtypes(include=["object"]).columns
if len(cat_cols) > 0:
    print("[+] Codificando columnas categóricas:", list(cat_cols))
    X = pd.get_dummies(X, columns=cat_cols)

# Codificar etiqueta a números (BENIGN → 0, ATTACK → 1/2/3/etc)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

print("[+] Clases detectadas:", label_encoder.classes_)

# Normalización
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Dividir dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

print("[✓] Dataset listo para entrenar")
print(f"✔ X_train: {X_train.shape}")
print(f"✔ X_test:  {X_test.shape}")
print(f"✔ y_train: {y_train.shape}")
print(f"✔ y_test:  {y_test.shape}")

#==============================================================================
# Modelo
#==============================================================================


import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense, BatchNormalization, Dropout
from keras.callbacks import EarlyStopping
from keras.optimizers import Adam

# ---------------------------------------------------------
# MLP PROFUNDO
# ---------------------------------------------------------

input_dim = X_train.shape[1]
num_classes = len(set(y_train))

print(f"[+] Dimensión de entrada: {input_dim}")
print(f"[+] Número de clases: {num_classes}")

# Modelo
model = Sequential([
    
    Dense(512, activation="relu", input_shape=(input_dim,)),
    BatchNormalization(),
    Dropout(0.3),

    Dense(256, activation="relu"),
    BatchNormalization(),
    Dropout(0.3),

    Dense(128, activation="relu"),
    BatchNormalization(),
    Dropout(0.2),

    Dense(64, activation="relu"),
    BatchNormalization(),
    Dropout(0.2),

    Dense(num_classes, activation="softmax")
])

# Optimizador más estable
optimizer = Adam(learning_rate=0.0008)

model.compile(
    optimizer=optimizer,
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)

# Callback para evitar overfitting
early_stop = EarlyStopping(
    monitor="val_loss",
    patience=8,
    restore_best_weights=True
)

print("[+] Entrenando modelo...")

history = model.fit(
    X_train, y_train,
    validation_split=0.2,
    epochs=80,
    batch_size=1024,
    callbacks=[early_stop],
    verbose=1
)

# Evaluación
loss, acc = model.evaluate(X_test, y_test, verbose=0)
print(f"[✓] Precisión en Test: {acc * 100:.2f}%")

# Guardar modelo
model.save("modelo_intrusion_MLP.h5")
print("[+] Modelo guardado como modelo_intrusion_MLP.h5")
