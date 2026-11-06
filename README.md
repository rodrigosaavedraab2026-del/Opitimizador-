# Optimizador PC (.exe para Windows 10/11)

Aplicación de un solo archivo (`OptimizadorPC.exe`, sin instalar nada) basada en tus
scripts de mantenimiento. Al abrirla pide permisos de Administrador (UAC) y muestra
una ventana con:

- **Diagnóstico**: RAM, discos, procesos, salud SMART, espacio recuperable (solo lectura).
- **Limpieza**: temporales, Prefetch, caché de Windows Update, miniaturas, caché de
  Chrome/Edge/Firefox (solo caché), papelera, DISM y DNS. Eliges qué limpiar.
- **Optimizar**: punto de restauración, plan de alto rendimiento, TRIM/desfragmentar,
  Sensor de almacenamiento, DNS, DISM CheckHealth.
- **Programas de inicio**: activar/desactivar con un interruptor (reversible).
- **Desinstalar**: lista con buscador; abre el desinstalador del programa.
- **Administrador**: hacer administrador a un usuario local.

Cerrar la ventana cierra el programa.

## Compilar
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o OptimizadorPC.exe .

## Seguridad
- El servidor escucha solo en 127.0.0.1, con puerto y token aleatorios; valida Host y Origin.
- El cliente nunca envía comandos: solo IDs; el comando de desinstalación se lee del registro.
- La limpieza solo vacía carpetas de temporales/caché conocidas y rechaza Documentos/Escritorio/Descargas.

## Descarga
Ve a **Releases** y descarga `Instalar-OptimizadorPC.exe` (instalador) u `OptimizadorPC.exe` (portátil).

## Recompilar el instalador
    # 1) compilar la app y copiarla al payload
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o installer/payload/OptimizadorPC.exe .
    # 2) compilar el instalador
    cd installer && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o ../Instalar-OptimizadorPC.exe .
