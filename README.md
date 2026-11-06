# Optimizador PC (Windows 10/11, 64 bits)

Aplicación de mantenimiento y optimización. Un solo `.exe` (sin instalar nada más) con interfaz propia,
tema claro/oscuro y todas las acciones reales sobre el sistema (nada simulado).

## Descarga
Carpeta **descargas/**: `Instalar-OptimizadorPC.exe` (instalador) u `OptimizadorPC.exe` (portátil).
El instalador acepta `/S` para instalar sin ventanas. Se desinstala desde *Aplicaciones instaladas*.

## Herramientas
| Sección | Qué hace |
|---|---|
| Panel | CPU/RAM en vivo, discos, puntuación de salud y recomendaciones con acceso directo |
| Limpieza | Temporales, Prefetch, Windows Update (detiene/reinicia el servicio), Delivery Optimization, WER, miniaturas, shaders, Chrome/Edge/Brave/Firefox (solo caché), papelera, DISM, DNS |
| Optimizar | Punto de restauración, plan de energía, TRIM/desfragmentar (`defrag /O`), Sensor de almacenamiento, DNS, hibernación |
| Programas de inicio | Registro Run (usuario/equipo/32 bits) y carpetas Inicio; activar/desactivar como el Administrador de tareas |
| Desinstalar | Programas clásicos y apps de la Tienda |
| Reparar Windows | DISM ScanHealth/RestoreHealth, SFC, CHKDSK (cancelable, salida en vivo) |
| Procesos | CPU y memoria reales por proceso; cerrar procesos (los críticos están protegidos) |
| Servicios | Iniciar/detener/cambiar tipo de inicio (los críticos están bloqueados) |
| Archivos grandes | Análisis de carpetas; envío a la Papelera (recuperable) |
| Archivos repetidos | Comparación por contenido (SHA-256); conserva siempre una copia |
| Red | Pruebas de conectividad, adaptadores, vaciar DNS, renovar IP, restablecer Winsock/TCP-IP |
| Ajustes de Windows | Privacidad, sugerencias, transparencia, animaciones, modo juego, extensiones, Inicio rápido, hibernación |
| Información | Hardware, BIOS, GPU, discos y salud SMART |
| Administrador | Hacer administrador a un usuario local |

## Cómo está hecho
- Go sin dependencias externas salvo `golang.org/x/sys`. Lecturas y cambios por **APIs nativas** (registro, procesos, servicios, discos, memoria);
  PowerShell solo para apps de la Tienda, usuarios locales, salud SMART y punto de restauración.
- Servidor HTTP solo en `127.0.0.1` con puerto y token aleatorios; valida `Host` y `Origin`. El cliente envía IDs, nunca comandos.
- Borrado a la Papelera solo para rutas devueltas por un análisis previo y fuera de Windows/Archivos de programa.
- Manifiesto `requireAdministrator` (aviso UAC nativo) e icono incrustados con `go-winres`.

## Compilar
    go install github.com/tc-hib/go-winres@v0.3.3
    go-winres make --in winres/winres.json --out rsrc
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o OptimizadorPC.exe .
    cp OptimizadorPC.exe installer/payload/
    cd installer && go-winres make --in winres/winres.json --out rsrc && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o ../Instalar-OptimizadorPC.exe .

Opciones de desarrollo del programa: `--no-elevate`, `--no-window`, `--test-token`.
