"""
Script de instalación para SPYNET V3.5.1
Configura el entorno y verifica las dependencias
"""

import os
import sys
import subprocess


def create_directory_structure():
    """Crea la estructura de directorios necesaria"""
    directories = [
        'core',
        'ui',
        'utils',
        'assets',
        'assets/img',
        'assets/geoip'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Directorio creado/verificado: {directory}/")


def create_init_files():
    """Crea los archivos __init__.py en los paquetes"""
    packages = ['core', 'ui', 'utils']
    
    for package in packages:
        init_file = os.path.join(package, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w', encoding='utf-8') as f:
                f.write(f'"""{package.capitalize()} package for SPYNET V3.5.1"""\n')
            print(f"✓ Creado: {init_file}")
        else:
            print(f"✓ Ya existe: {init_file}")


def install_dependencies():
    """Instala las dependencias desde requirements.txt"""
    if not os.path.exists('requirements.txt'):
        print("⚠ requirements.txt no encontrado. Saltando instalación de dependencias.")
        return
    
    print("\n📦 Instalando dependencias...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("✓ Dependencias instaladas correctamente")
    except subprocess.CalledProcessError as e:
        print(f"✗ Error al instalar dependencias: {e}")
        print("  Puedes intentar manualmente: pip install -r requirements.txt")


def check_geoip_database():
    """Verifica la presencia de la base de datos GeoIP"""
    geoip_path = os.path.join('assets', 'geoip', 'GeoLite2-City.mmdb')
    
    if os.path.exists(geoip_path):
        print(f"✓ Base de datos GeoIP encontrada: {geoip_path}")
    else:
        print(f"\n⚠ Base de datos GeoIP NO encontrada en: {geoip_path}")
        print("  Descárgala de: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        print("  La geolocalización estará deshabilitada hasta que la instales.")


def main():
    """Función principal de setup"""
    print("=" * 70)
    print("SPYNET V3.5.1 - Script de Configuración")
    print("=" * 70)
    print()
    
    print("🔧 Creando estructura de directorios...")
    create_directory_structure()
    print()
    
    print("📝 Creando archivos de inicialización...")
    create_init_files()
    print()
    
    # Preguntar si instalar dependencias
    response = input("¿Deseas instalar las dependencias ahora? (s/n): ").lower()
    if response in ['s', 'si', 'y', 'yes']:
        install_dependencies()
    else:
        print("⏭ Saltando instalación de dependencias.")
        print("  Recuerda instalarlas más tarde con: pip install -r requirements.txt")
    print()
    
    print("🌍 Verificando base de datos GeoIP...")
    check_geoip_database()
    print()
    
    print("=" * 70)
    print("✅ Configuración completada!")
    print("=" * 70)
    print()
    print("Para ejecutar SPYNET:")
    print("  python main.py")
    print()
    print("Recuerda ejecutar con privilegios de administrador/sudo")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Configuración cancelada por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n✗ Error durante la configuración: {e}")
        sys.exit(1)