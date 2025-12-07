"""
==============================================================================
train_ai_model.py
Script para entrenar el modelo CNN de detección de anomalías de red
Usa el dataset CICIDS2017 optimizado para 20 features
==============================================================================
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils import class_weight
import tensorflow as tf
from tensorflow import keras
from keras import layers, models, callbacks
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# ==================== CONFIGURACIÓN ====================
DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"
# Descargar manualmente desde Kaggle o la fuente oficial:
# https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset
# O desde: https://www.unb.ca/cic/datasets/ids-2017.html

# RUTAS (ajusta según tu estructura)
DATASET_PATH = "cicids2017_sample.csv"  # Archivo CSV del dataset
MODEL_SAVE_PATH = "models/network_anomaly_cnn.keras"
SCALER_SAVE_PATH = "models/scaler.pkl"

# PARÁMETROS DE ENTRENAMIENTO
N_FEATURES = 20  # Debe coincidir con anomaly_detector.py
BATCH_SIZE = 128
EPOCHS = 50
VALIDATION_SPLIT = 0.2
TEST_SIZE = 0.15
RANDOM_STATE = 42

# Mapeo de clases (4 categorías)
CLASS_MAPPING = {
    'BENIGN': 0,
    'DoS Hulk': 1, 'DoS GoldenEye': 1, 'DoS slowloris': 1, 'DoS Slowhttptest': 1,
    'DDoS': 1, 'Heartbleed': 1,
    'PortScan': 2, 'FTP-Patator': 2, 'SSH-Patator': 2, 'Infiltration': 2,
    'Bot': 2, 'Brute Force': 2, 'Web Attack': 2,
    'Web Attack â€" Brute Force': 2, 'Web Attack â€" XSS': 2, 'Web Attack â€" Sql Injection': 2,
}

# ==================== FUNCIONES DE PREPROCESAMIENTO ====================

def download_dataset_instructions():
    """Instrucciones para descargar el dataset"""
    print("="*70)
    print("INSTRUCCIONES PARA OBTENER EL DATASET CICIDS2017")
    print("="*70)
    print("\nOPCIÓN 1 - Kaggle (Recomendado - Más rápido):")
    print("  1. Ve a: https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset")
    print("  2. Descarga 'MachineLearningCVE/MachineLearningCSV.zip'")
    print("  3. Descomprime y combina los CSVs en uno solo")
    print("  4. Renombra como 'cicids2017_sample.csv' en la misma carpeta")
    print("\nOPCIÓN 2 - Fuente Oficial:")
    print("  1. Ve a: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("  2. Descarga el dataset completo")
    print("  3. Extrae los archivos CSV")
    print("\nOPCIÓN 3 - Usar muestra reducida (para pruebas):")
    print("  El script puede generar un dataset sintético de ejemplo")
    print("="*70)

def create_sample_dataset(n_samples=50000):
    """
    Crea un dataset sintético de ejemplo para pruebas.
    ADVERTENCIA: NO es real, solo para demostración.
    """
    print("\n⚠️ CREANDO DATASET SINTÉTICO DE PRUEBA...")
    print("Para mejores resultados, usa el dataset CICIDS2017 real.\n")
    
    np.random.seed(RANDOM_STATE)
    
    # Generar features sintéticas
    data = {
        'Flow Duration': np.random.randint(0, 1000000, n_samples),
        'Total Fwd Packets': np.random.randint(0, 500, n_samples),
        'Total Backward Packets': np.random.randint(0, 500, n_samples),
        'Total Length of Fwd Packets': np.random.randint(0, 100000, n_samples),
        'Total Length of Bwd Packets': np.random.randint(0, 100000, n_samples),
        'Fwd Packet Length Max': np.random.randint(0, 1500, n_samples),
        'Fwd Packet Length Min': np.random.randint(0, 100, n_samples),
        'Fwd Packet Length Mean': np.random.uniform(0, 1000, n_samples),
        'Fwd Packet Length Std': np.random.uniform(0, 500, n_samples),
        'Bwd Packet Length Max': np.random.randint(0, 1500, n_samples),
        'Bwd Packet Length Min': np.random.randint(0, 100, n_samples),
        'Bwd Packet Length Mean': np.random.uniform(0, 1000, n_samples),
        'Bwd Packet Length Std': np.random.uniform(0, 500, n_samples),
        'Flow Bytes/s': np.random.uniform(0, 1000000, n_samples),
        'Flow Packets/s': np.random.uniform(0, 10000, n_samples),
        'Flow IAT Mean': np.random.uniform(0, 1000000, n_samples),
        'Flow IAT Std': np.random.uniform(0, 500000, n_samples),
        'Flow IAT Max': np.random.randint(0, 2000000, n_samples),
        'Flow IAT Min': np.random.randint(0, 100000, n_samples),
        'Fwd IAT Total': np.random.randint(0, 1000000, n_samples),
    }
    
    # Generar etiquetas (70% normal, 30% ataques)
    labels = []
    for _ in range(n_samples):
        rand = np.random.random()
        if rand < 0.70:
            labels.append('BENIGN')
        elif rand < 0.85:
            labels.append(np.random.choice(['DoS Hulk', 'DDoS', 'DoS slowloris']))
        elif rand < 0.95:
            labels.append(np.random.choice(['PortScan', 'FTP-Patator', 'SSH-Patator']))
        else:
            labels.append('Bot')
    
    data['Label'] = labels
    
    df = pd.DataFrame(data)
    df.to_csv(DATASET_PATH, index=False)
    print(f"✅ Dataset sintético guardado en: {DATASET_PATH}")
    return df

def load_and_prepare_data():
    """Carga y prepara el dataset CICIDS2017"""
    
    # Verificar si existe el dataset
    if not os.path.exists(DATASET_PATH):
        print(f"\n❌ No se encontró el dataset: {DATASET_PATH}")
        download_dataset_instructions()
        
        response = input("\n¿Quieres crear un dataset sintético para pruebas? (s/n): ")
        if response.lower() == 's':
            df = create_sample_dataset()
        else:
            print("\nSaliendo... Por favor descarga el dataset y vuelve a ejecutar.")
            exit()
    else:
        print(f"\n✅ Cargando dataset desde: {DATASET_PATH}")
        df = pd.read_csv(DATASET_PATH)
    
    print(f"📊 Dataset cargado: {df.shape[0]} filas, {df.shape[1]} columnas")
    
    # Verificar que exista la columna Label
    if 'Label' not in df.columns:
        if ' Label' in df.columns:
            df.rename(columns={' Label': 'Label'}, inplace=True)
        else:
            raise ValueError("No se encontró la columna 'Label' en el dataset")
    
    # Limpiar nombres de columnas (quitar espacios)
    df.columns = df.columns.str.strip()
    
    # Mostrar distribución de clases
    print("\n📈 Distribución de clases original:")
    print(df['Label'].value_counts())
    
    return df

def select_features(df):
    """
    Selecciona las 20 features más relevantes del dataset.
    Estas deben corresponder a las que extrae _extract_features_dl()
    """
    # Las 20 features más importantes según análisis del CICIDS2017
    important_features = [
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Total'
    ]
    
    # Verificar qué features existen en el dataset
    available_features = [f for f in important_features if f in df.columns]
    
    if len(available_features) < N_FEATURES:
        print(f"\n⚠️ Solo {len(available_features)} de {N_FEATURES} features disponibles")
        # Rellenar con las primeras columnas numéricas disponibles
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        numeric_cols = [c for c in numeric_cols if c not in available_features]
        available_features.extend(numeric_cols[:N_FEATURES - len(available_features)])
    
    # Tomar solo las primeras N_FEATURES
    selected_features = available_features[:N_FEATURES]
    
    print(f"\n✅ Features seleccionadas ({len(selected_features)}):")
    for i, feat in enumerate(selected_features, 1):
        print(f"  {i}. {feat}")
    
    return selected_features

def map_labels(df):
    """Mapea las etiquetas a las 4 clases principales"""
    
    # Crear mapeo genérico para cualquier ataque no listado
    def categorize_label(label):
        if label in CLASS_MAPPING:
            return CLASS_MAPPING[label]
        # Si es BENIGN
        if 'BENIGN' in label.upper():
            return 0
        # Si es DoS/DDoS
        if 'DOS' in label.upper() or 'DDOS' in label.upper():
            return 1
        # Cualquier otro ataque -> Intrusión
        return 2
    
    df['Label_Encoded'] = df['Label'].apply(categorize_label)
    
    # Mostrar distribución final
    label_names = {0: "Normal", 1: "DoS Attack", 2: "Intrusión", 3: "DNS Attack"}
    print("\n📊 Distribución final de clases:")
    for code, count in df['Label_Encoded'].value_counts().sort_index().items():
        name = label_names.get(code, f"Clase {code}")
        print(f"  {code} ({name}): {count:,} muestras ({count/len(df)*100:.2f}%)")
    
    return df

def preprocess_data(df, selected_features):
    """Preprocesa los datos: limpieza, normalización y split"""
    
    # Extraer features y labels
    X = df[selected_features].values
    y = df['Label_Encoded'].values
    
    # Manejar valores infinitos y NaN
    X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=-1e10)
    
    print(f"\n📐 Forma de X: {X.shape}")
    print(f"📐 Forma de y: {y.shape}")
    
    # Split: Train + Val (85%) y Test (15%)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    
    # Split interno: Train (80%) y Val (20% del 85%)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=VALIDATION_SPLIT, random_state=RANDOM_STATE, stratify=y_temp
    )
    
    print(f"\n📦 División del dataset:")
    print(f"  Entrenamiento: {X_train.shape[0]:,} muestras")
    print(f"  Validación:    {X_val.shape[0]:,} muestras")
    print(f"  Prueba:        {X_test.shape[0]:,} muestras")
    
    # Normalización con StandardScaler
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)
    
    # Guardar el scaler
    os.makedirs(os.path.dirname(SCALER_SAVE_PATH), exist_ok=True)
    joblib.dump(scaler, SCALER_SAVE_PATH)
    print(f"\n💾 Scaler guardado en: {SCALER_SAVE_PATH}")
    
    # Reshape para CNN: (samples, features, 1)
    X_train = X_train.reshape(X_train.shape[0], N_FEATURES, 1)
    X_val = X_val.reshape(X_val.shape[0], N_FEATURES, 1)
    X_test = X_test.reshape(X_test.shape[0], N_FEATURES, 1)
    
    return (X_train, y_train), (X_val, y_val), (X_test, y_test), scaler

# ==================== CONSTRUCCIÓN DEL MODELO ====================

def build_cnn_model(num_classes=4):
    """
    Construye el modelo CNN 1D para detección de anomalías.
    Arquitectura optimizada para 20 features.
    """
    model = models.Sequential([
        # Capa de entrada
        layers.Input(shape=(N_FEATURES, 1)),
        
        # Bloque Convolucional 1
        layers.Conv1D(filters=64, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),
        
        # Bloque Convolucional 2
        layers.Conv1D(filters=128, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),
        
        # Bloque Convolucional 3
        layers.Conv1D(filters=256, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.GlobalMaxPooling1D(),
        
        # Capas Densas
        layers.Dense(256, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.5),
        
        layers.Dense(128, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.4),
        
        # Capa de salida
        layers.Dense(num_classes, activation='softmax')
    ])
    
    # Compilar el modelo
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
    )
    
    return model

# ==================== ENTRENAMIENTO ====================

def train_model(model, train_data, val_data, class_weights):
    """Entrena el modelo CNN"""
    
    X_train, y_train = train_data
    X_val, y_val = val_data
    
    # Callbacks
    early_stop = callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True,
        verbose=1
    )
    
    reduce_lr = callbacks.ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=5,
        min_lr=1e-7,
        verbose=1
    )
    
    checkpoint = callbacks.ModelCheckpoint(
        MODEL_SAVE_PATH,
        monitor='val_accuracy',
        save_best_only=True,
        verbose=1
    )
    
    # Entrenar
    print("\n🚀 INICIANDO ENTRENAMIENTO...")
    print("="*70)
    
    history = model.fit(
        X_train, y_train,
        batch_size=BATCH_SIZE,
        epochs=EPOCHS,
        validation_data=(X_val, y_val),
        class_weight=class_weights,
        callbacks=[early_stop, reduce_lr, checkpoint],
        verbose=1
    )
    
    return history

# ==================== EVALUACIÓN ====================

def evaluate_model(model, test_data):
    """Evalúa el modelo en el conjunto de prueba"""
    
    X_test, y_test = test_data
    
    print("\n📊 EVALUANDO MODELO EN CONJUNTO DE PRUEBA...")
    print("="*70)
    
    # Evaluación general
    test_loss, test_acc, test_prec, test_rec = model.evaluate(X_test, y_test, verbose=0)
    
    print(f"\n✅ Resultados del Test:")
    print(f"  Loss:      {test_loss:.4f}")
    print(f"  Accuracy:  {test_acc*100:.2f}%")
    print(f"  Precision: {test_prec*100:.2f}%")
    print(f"  Recall:    {test_rec*100:.2f}%")
    print(f"  F1-Score:  {2*(test_prec*test_rec)/(test_prec+test_rec)*100:.2f}%")
    
    # Predicciones
    y_pred = model.predict(X_test, verbose=0)
    y_pred_classes = np.argmax(y_pred, axis=1)
    
    # Matriz de confusión
    from sklearn.metrics import confusion_matrix, classification_report
    
    cm = confusion_matrix(y_test, y_pred_classes)
    
    class_names = ["Normal", "DoS Attack", "Intrusión", "DNS Attack"]
    
    print("\n📋 Reporte de Clasificación:")
    print(classification_report(y_test, y_pred_classes, target_names=class_names))
    
    # Visualizar matriz de confusión
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=class_names, yticklabels=class_names)
    plt.title('Matriz de Confusión - Detección de Anomalías')
    plt.ylabel('Verdadero')
    plt.xlabel('Predicho')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=300)
    print("\n💾 Matriz de confusión guardada en: confusion_matrix.png")

def plot_training_history(history):
    """Grafica el historial de entrenamiento"""
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # Accuracy
    axes[0, 0].plot(history.history['accuracy'], label='Train')
    axes[0, 0].plot(history.history['val_accuracy'], label='Validation')
    axes[0, 0].set_title('Model Accuracy')
    axes[0, 0].set_ylabel('Accuracy')
    axes[0, 0].set_xlabel('Epoch')
    axes[0, 0].legend()
    axes[0, 0].grid(True)
    
    # Loss
    axes[0, 1].plot(history.history['loss'], label='Train')
    axes[0, 1].plot(history.history['val_loss'], label='Validation')
    axes[0, 1].set_title('Model Loss')
    axes[0, 1].set_ylabel('Loss')
    axes[0, 1].set_xlabel('Epoch')
    axes[0, 1].legend()
    axes[0, 1].grid(True)
    
    # Precision
    axes[1, 0].plot(history.history['precision'], label='Train')
    axes[1, 0].plot(history.history['val_precision'], label='Validation')
    axes[1, 0].set_title('Model Precision')
    axes[1, 0].set_ylabel('Precision')
    axes[1, 0].set_xlabel('Epoch')
    axes[1, 0].legend()
    axes[1, 0].grid(True)
    
    # Recall
    axes[1, 1].plot(history.history['recall'], label='Train')
    axes[1, 1].plot(history.history['val_recall'], label='Validation')
    axes[1, 1].set_title('Model Recall')
    axes[1, 1].set_ylabel('Recall')
    axes[1, 1].set_xlabel('Epoch')
    axes[1, 1].legend()
    axes[1, 1].grid(True)
    
    plt.tight_layout()
    plt.savefig('training_history.png', dpi=300)
    print("\n💾 Historial de entrenamiento guardado en: training_history.png")

# ==================== FUNCIÓN PRINCIPAL ====================

def main():
    """Función principal de entrenamiento"""
    
    print("\n" + "="*70)
    print(" 🧠 ENTRENAMIENTO DE IA PARA DETECCIÓN DE ANOMALÍAS DE RED")
    print("="*70)
    
    # 1. Cargar dataset
    df = load_and_prepare_data()
    
    # 2. Seleccionar features
    selected_features = select_features(df)
    
    # 3. Mapear etiquetas
    df = map_labels(df)
    
    # 4. Preprocesar datos
    train_data, val_data, test_data, scaler = preprocess_data(df, selected_features)
    
    # 5. Calcular pesos de clase (para balancear dataset desbalanceado)
    class_weights_array = class_weight.compute_class_weight(
        'balanced',
        classes=np.unique(train_data[1]),
        y=train_data[1]
    )
    class_weights = dict(enumerate(class_weights_array))
    
    print(f"\n⚖️ Pesos de clase calculados:")
    for cls, weight in class_weights.items():
        print(f"  Clase {cls}: {weight:.4f}")
    
    # 6. Construir modelo
    print("\n🏗️ CONSTRUYENDO MODELO CNN...")
    model = build_cnn_model(num_classes=4)
    model.summary()
    
    # 7. Entrenar modelo
    history = train_model(model, train_data, val_data, class_weights)
    
    # 8. Evaluar modelo
    evaluate_model(model, test_data)
    
    # 9. Graficar historial
    plot_training_history(history)
    
    print("\n" + "="*70)
    print(" ✅ ENTRENAMIENTO COMPLETADO")
    print("="*70)
    print(f"\n📁 Archivos generados:")
    print(f"  - Modelo:  {MODEL_SAVE_PATH}")
    print(f"  - Scaler:  {SCALER_SAVE_PATH}")
    print(f"  - Gráficas: confusion_matrix.png, training_history.png")
    print("\n💡 Puedes ahora usar estos archivos en tu aplicación de análisis de red.")

if __name__ == "__main__":
    main()