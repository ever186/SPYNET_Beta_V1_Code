# ==============================================================================
# utils/ai_export.py
# Exportador de resultados de IA a CSV
# ==============================================================================

import csv
from datetime import datetime
from tkinter import filedialog, messagebox
import os
import sys


def export_ai_results_to_csv(ai_tree, stats, parent_window):
    """
    Exporta las alertas de IA visibles en el Treeview a un archivo CSV.
    Si no hay alertas, exporta solo las estadísticas.
    """
    
    # Verificar si hay paquetes analizados
    if stats.get('scanned', 0) == 0:
        messagebox.showinfo(
            "Sin Datos", 
            "No hay paquetes analizados todavía.\n\nInicia la captura de tráfico primero.",
            parent=parent_window
        )
        return
    
    try:
        # Generar nombre de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"spynet_ai_report_{timestamp}.csv"
        
        # Diálogo para guardar archivo
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=default_filename,
            filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")],
            title="Exportar Reporte de IA a CSV",
            parent=parent_window
        )
        
        # Si el usuario cancela
        if not filepath:
            return
        
        # Contar alertas
        total_alerts = len(ai_tree.get_children())
        
        # Escribir el archivo CSV
        with open(filepath, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # === ENCABEZADO DEL REPORTE ===
            writer.writerow(["=" * 80])
            writer.writerow(["SPYNET V1.0.0 - REPORTE DE ANALISIS DE INTELIGENCIA ARTIFICIAL"])
            writer.writerow(["=" * 80])
            writer.writerow([f"Fecha de Generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
            writer.writerow([])
            
            # === ESTADÍSTICAS GENERALES ===
            writer.writerow(["ESTADiSTICAS GENERALES"])
            writer.writerow(["-" * 80])
            writer.writerow(["Metrica", "Valor"])
            writer.writerow(["Paquetes Analizados por IA", stats.get('scanned', 0)])
            writer.writerow(["Alertas Sospechosas (Warning)", stats.get('suspicious', 0)])
            writer.writerow(["Alertas Criticas (Ataques)", stats.get('critical', 0)])
            writer.writerow(["Total de Amenazas Detectadas", total_alerts])
            
            # Calcular nivel de amenaza
            total_threats = stats.get('suspicious', 0) + stats.get('critical', 0)
            if stats.get('critical', 0) > 5:
                threat_level = "ALTO"
            elif total_threats > 0:
                threat_level = "MEDIO"
            else:
                threat_level = "BAJO"
            
            writer.writerow(["Nivel de Amenaza Detectado", threat_level])
            
            # Calcular porcentaje de amenazas
            scanned = stats.get('scanned', 0)
            if scanned > 0:
                threat_percentage = (total_threats / scanned) * 100
                writer.writerow(["Porcentaje de Trafico Malicioso", f"{threat_percentage:.2f}%"])
            
            writer.writerow([])
            
            # === DETALLE DE ALERTAS ===
            writer.writerow(["DETALLE DE ALERTAS DETECTADAS"])
            writer.writerow(["-" * 80])
            
            # Verificar si hay alertas
            if total_alerts == 0:
                writer.writerow(["Estado", "SIN AMENAZAS DETECTADAS"])
                writer.writerow(["Descripcion", "El modelo de IA analizó el tráfico y no encontró patrones sospechosos."])
                writer.writerow(["Recomendacion", "Continuar monitoreando el tráfico de red regularmente."])
            else:
                # Encabezados de la tabla de alertas
                writer.writerow([
                    "Timestamp",
                    "Tipo de Ataque",
                    "IP Origen",
                    "IP Destino",
                    "Confianza (%)",
                    "Severidad"
                ])
                
                # Datos de las alertas
                for child_id in ai_tree.get_children():
                    values = ai_tree.item(child_id)['values']
                    tags = ai_tree.item(child_id)['tags']
                    
                    # Determinar severidad por el tag
                    if 'critical' in tags:
                        severity = "CRITICO"
                    elif 'suspicious' in tags:
                        severity = "SOSPECHOSO"
                    else:
                        severity = "NORMAL"
                    
                    # Escribir fila con todos los valores
                    writer.writerow([
                        values[0],  # Timestamp
                        values[1],  # Tipo de Ataque
                        values[2],  # IP Origen
                        values[3],  # IP Destino
                        values[4],  # Confianza
                        severity    # Severidad
                    ])
            
            # === PIE DE PÁGINA ===
            writer.writerow([])
            writer.writerow(["=" * 80])
            writer.writerow(["Fin del Reporte"])
            writer.writerow(["Generado por SPYNET - Network Security Analyzer"])
            writer.writerow(["=" * 80])
        
        # Mensaje de confirmación personalizado
        if total_alerts == 0:
            mensaje_confirmacion = (
                f"✅ Reporte de IA exportado correctamente a:\n\n{filepath}\n\n"
                f"📊 Estadisticas:\n"
                f"   • Paquetes analizados: {stats.get('scanned', 0)}\n"
                f"   • Amenazas detectadas: 0\n"
                f"   • Estado: RED SEGURA"
            )
        else:
            mensaje_confirmacion = (
                f"⚠️ Reporte de IA exportado correctamente a:\n\n{filepath}\n\n"
                f"📊 Estadisticas:\n"
                f"   • Paquetes analizados: {stats.get('scanned', 0)}\n"
                f"   • Alertas sospechosas: {stats.get('suspicious', 0)}\n"
                f"   • Alertas criticas: {stats.get('critical', 0)}\n"
                f"   • Total de amenazas: {total_alerts}"
            )
        
        # Confirmar exportación exitosa
        messagebox.showinfo(
            "Exportación Exitosa", 
            mensaje_confirmacion,
            parent=parent_window
        )
        
        # Preguntar si desea abrir el archivo
        if messagebox.askyesno(
            "Abrir Archivo", 
            "¿Deseas abrir el archivo CSV ahora?", 
            parent=parent_window
        ):
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(filepath)
                elif os.name == 'posix':  # macOS/Linux
                    os.system(f'open "{filepath}"' if sys.platform == 'darwin' else f'xdg-open "{filepath}"')
            except Exception as e:
                messagebox.showwarning(
                    "Advertencia",
                    f"No se pudo abrir el archivo automaticamente:\n{e}\n\nPuedes abrirlo manualmente desde:\n{filepath}",
                    parent=parent_window
                )
            
    except PermissionError:
        messagebox.showerror(
            "Error de Permisos", 
            f"No se puede escribir en:\n{filepath}\n\nVerifica que:\n• El archivo no esté abierto\n• Tengas permisos de escritura",
            parent=parent_window
        )
    except Exception as e:
        messagebox.showerror(
            "Error de Exportación", 
            f"No se pudo exportar el reporte.\n\nDetalles del error:\n{e}",
            parent=parent_window
        )
