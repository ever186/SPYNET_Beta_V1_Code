# ==============================================================================
# utils/file_operations.py
# Guardar/cargar sesiones, exportar CSV
# ==============================================================================

import pickle
import csv
from tkinter import filedialog, messagebox
from datetime import datetime
from config import CSV_EXPORT_FORMAT, SESSION_FILE_EXTENSION

def save_session_data(all_packets_data, parent_window):
    """
    Guarda los datos de la sesión de captura (all_packets_data) en un archivo.
    """
    if not all_packets_data:
        messagebox.showinfo("Sin Datos", "No hay datos de captura para guardar.", parent=parent_window)
        return
    
    try:
        filepath = filedialog.asksaveasfilename(
            defaultextension=SESSION_FILE_EXTENSION,
            filetypes=[("SPYNET Session Files", f"*{SESSION_FILE_EXTENSION}"), ("All Files", "*.*")],
            title="Guardar Sesión de Captura"
        )
        if not filepath:
            return

        with open(filepath, 'wb') as f:
            pickle.dump(all_packets_data, f)
        messagebox.showinfo("Éxito", f"Sesión guardada correctamente en:\n{filepath}", parent=parent_window)
    except Exception as e:
        messagebox.showerror("Error al Guardar", f"No se pudo guardar la sesión: {e}", parent=parent_window)

def load_session_data(parent_window):
    """
    Carga datos de una sesión de captura desde un archivo.
    Devuelve los datos cargados o None si falla.
    """
    if not messagebox.askyesno("Confirmar Carga", "¿Cargar una nueva sesión? Los datos actuales se borrarán.", parent=parent_window):
        return None
        
    try:
        filepath = filedialog.askopenfilename(
            filetypes=[("SPYNET Session Files", f"*{SESSION_FILE_EXTENSION}"), ("All Files", "*.*")],
            title="Cargar Sesión de Captura"
        )
        if not filepath:
            return None

        with open(filepath, 'rb') as f:
            loaded_data = pickle.load(f)
        
        messagebox.showinfo("Éxito", f"Sesión cargada desde:\n{filepath}", parent=parent_window)
        return loaded_data
        
    except Exception as e:
        messagebox.showerror("Error al Cargar", f"No se pudo cargar la sesión: {e}", parent=parent_window)
        return None

def export_csv_data(traffic_tree, parent_window):
    """
    Exporta los datos actualmente visibles en el Treeview a un archivo CSV.
    """
    if not traffic_tree.get_children():
        messagebox.showinfo("Sin Datos", "No hay datos en la tabla para exportar.", parent=parent_window)
        return
        
    try:
        filename = datetime.now().strftime(CSV_EXPORT_FORMAT)
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Tiempo", "País", "Origen", "Destino", "Dominio", "Protocolo", "Puerto", "Tamaño", "Detalles"])
            for child_id in traffic_tree.get_children():
                writer.writerow(traffic_tree.item(child_id)['values'])
        messagebox.showinfo("Exportación Exitosa", f"Datos exportados a: {filename}", parent=parent_window)
    except Exception as e:
        messagebox.showerror("Error de Exportación", f"No se pudo exportar: {e}", parent=parent_window)