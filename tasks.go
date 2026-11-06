package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ------------------------------------------------------------ utilidades

func fmtSize(b int64) string {
	f := float64(b)
	switch {
	case f >= 1<<30:
		return fmt.Sprintf("%.2f GB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.2f MB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.2f KB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

// dirSize suma el tamano de una carpeta ignorando errores (archivos en uso, permisos).
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if info, e := d.Info(); e == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// vaciarCarpeta borra el CONTENIDO de una carpeta (no la carpeta en si).
// Los archivos en uso se ignoran. Devuelve los bytes liberados.
func vaciarCarpeta(dir string) int64 {
	if !carpetaSegura(dir) {
		return 0
	}
	before := dirSize(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
	after := dirSize(dir)
	if before < after {
		return 0
	}
	return before - after
}

// carpetaSegura: red de seguridad para no vaciar nunca una raiz o carpeta personal por error.
func carpetaSegura(dir string) bool {
	d := filepath.Clean(dir)
	if len(d) < 8 || d == filepath.VolumeName(d)+string(filepath.Separator) {
		return false
	}
	low := strings.ToLower(d)
	for _, bad := range []string{"documents", "documentos", "desktop", "escritorio", "pictures", "imagenes", "downloads", "descargas"} {
		if strings.HasSuffix(low, string(filepath.Separator)+bad) {
			return false
		}
	}
	return true
}

func env(k string) string { return os.Getenv(k) }

func join(parts ...string) string {
	for _, p := range parts {
		if p == "" {
			return ""
		}
	}
	return filepath.Join(parts...)
}

// glob de carpetas de perfil de navegador (Default, Profile 1, ...)
func perfilesChromium(userData string, sub ...string) []string {
	if userData == "" {
		return nil
	}
	var out []string
	cands, _ := filepath.Glob(filepath.Join(userData, "*"))
	for _, c := range cands {
		b := filepath.Base(c)
		if b == "Default" || strings.HasPrefix(b, "Profile ") {
			for _, s := range sub {
				out = append(out, filepath.Join(c, s))
			}
		}
	}
	return out
}

// ------------------------------------------------------------ limpieza

type limpItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	Bytes   int64  `json:"bytes"`
	Default bool   `json:"default"`
	Manual  bool   `json:"manual"` // sin tamano estimable (accion directa)
	paths   []string
	files   []string // globs de archivos sueltos
}

func catalogoLimpieza() []*limpItem {
	local := env("LOCALAPPDATA")
	win := env("WINDIR")
	if win == "" {
		win = env("SystemRoot")
	}
	firefox := []string{}
	if local != "" {
		profs, _ := filepath.Glob(filepath.Join(local, "Mozilla", "Firefox", "Profiles", "*"))
		for _, p := range profs {
			firefox = append(firefox, filepath.Join(p, "cache2"), filepath.Join(p, "startupCache"))
		}
	}
	return []*limpItem{
		{ID: "temp_user", Name: "Temporales del usuario", Desc: "Carpeta %TEMP%", Default: true, paths: []string{env("TEMP")}},
		{ID: "temp_win", Name: "Temporales de Windows", Desc: "C:\\Windows\\Temp", Default: true, paths: []string{join(win, "Temp")}},
		{ID: "prefetch", Name: "Prefetch", Desc: "Datos de precarga de programas", Default: true, paths: []string{join(win, "Prefetch")}},
		{ID: "wu_cache", Name: "Caché de Windows Update", Desc: "Descargas de actualizaciones ya instaladas", Default: true, paths: []string{join(win, "SoftwareDistribution", "Download")}},
		{ID: "crash", Name: "Volcados de errores", Desc: "Crash dumps de aplicaciones", Default: true, paths: []string{join(local, "CrashDumps")}},
		{ID: "thumbs", Name: "Caché de miniaturas", Desc: "thumbcache_*.db del Explorador", Default: true, files: []string{join(local, "Microsoft", "Windows", "Explorer", "thumbcache_*.db")}},
		{ID: "chrome", Name: "Caché de Chrome", Desc: "Solo caché, no contraseñas ni historial (cierra Chrome)", Default: true,
			paths: perfilesChromium(join(local, "Google", "Chrome", "User Data"), "Cache", "Code Cache", "GPUCache")},
		{ID: "edge", Name: "Caché de Edge", Desc: "Solo caché, no contraseñas ni historial", Default: true,
			paths: perfilesChromium(join(local, "Microsoft", "Edge", "User Data"), "Cache", "Code Cache", "GPUCache")},
		{ID: "firefox", Name: "Caché de Firefox", Desc: "Solo caché, no contraseñas ni historial", Default: true, paths: firefox},
		{ID: "recycle", Name: "Papelera de reciclaje", Desc: "Vacía la papelera de todas las unidades", Default: true, Manual: true},
		{ID: "dism", Name: "Limpieza profunda de componentes (DISM)", Desc: "StartComponentCleanup. Tarda varios minutos", Default: false, Manual: true},
		{ID: "dns", Name: "Vaciar caché DNS", Desc: "ipconfig /flushdns", Default: true, Manual: true},
	}
}

func scanLimpieza() []*limpItem {
	items := catalogoLimpieza()
	for _, it := range items {
		for _, p := range it.paths {
			if p != "" && carpetaSegura(p) {
				it.Bytes += dirSize(p)
			}
		}
		for _, g := range it.files {
			if g == "" {
				continue
			}
			ms, _ := filepath.Glob(g)
			for _, m := range ms {
				if st, err := os.Stat(m); err == nil {
					it.Bytes += st.Size()
				}
			}
		}
	}
	return items
}

func runLimpieza(j *Job, ids []string) {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	var total int64
	j.log("== LIMPIEZA ==")
	for _, it := range catalogoLimpieza() {
		if !sel[it.ID] {
			continue
		}
		switch it.ID {
		case "recycle":
			if err := runPS(j, "Clear-RecycleBin -Force -ErrorAction Stop", nil); err != nil {
				j.log("[!!] Papelera ya vacía o no accesible")
			} else {
				j.log("[OK] Papelera de reciclaje vaciada")
			}
		case "dism":
			j.log("Limpieza profunda de componentes (puede tardar varios minutos)...")
			if err := runNative(j, "Dism.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"); err != nil {
				j.log("[!!] DISM no completó la limpieza: " + err.Error())
			} else {
				j.log("[OK] Componentes de Windows optimizados")
			}
		case "dns":
			if err := runNative(j, "ipconfig", "/flushdns"); err != nil {
				j.log("[!!] No se pudo vaciar la caché DNS")
			} else {
				j.log("[OK] Caché DNS vaciada")
			}
		default:
			var lib int64
			for _, p := range it.paths {
				if p != "" {
					lib += vaciarCarpeta(p)
				}
			}
			for _, g := range it.files {
				if g == "" {
					continue
				}
				ms, _ := filepath.Glob(g)
				for _, m := range ms {
					if st, err := os.Stat(m); err == nil && os.Remove(m) == nil {
						lib += st.Size()
					}
				}
			}
			total += lib
			j.log(fmt.Sprintf("[OK] %-40s liberado: %s", it.Name, fmtSize(lib)))
		}
	}
	j.log("")
	j.log("[OK] LIMPIEZA COMPLETADA. Espacio liberado (aprox.): " + fmtSize(total))
}

// ------------------------------------------------------------ optimizar

func runOptimizar(j *Job, ids []string) {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	j.log("== OPTIMIZACIÓN (modo seguro, reversible) ==")

	if sel["restore"] {
		j.log("Creando punto de restauración...")
		err := runPS(j, `Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue; Checkpoint-Computer -Description "Optimizador PC" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop`, nil)
		if err != nil {
			j.log("[!!] No se pudo crear el punto de restauración (Windows solo permite uno cada 24 h o está desactivado)")
		} else {
			j.log("[OK] Punto de restauración creado")
		}
	}
	if sel["power"] {
		if err := runNative(j, "powercfg", "/setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"); err != nil {
			_ = runNative(j, "powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61")
			if err2 := runNative(j, "powercfg", "/setactive", "e9a42b02-d5df-448d-aa00-03f14749eb61"); err2 != nil {
				j.log("[!!] No se pudo cambiar el plan de energía (puede no estar disponible en este equipo)")
			} else {
				j.log("[OK] Plan de energía 'Máximo rendimiento' activado")
			}
		} else {
			j.log("[OK] Plan de energía de alto rendimiento activado")
		}
	}
	if sel["trim"] {
		j.log("Optimizando discos (TRIM en SSD / desfragmentación en HDD)...")
		err := runPS(j, `Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' } | ForEach-Object {
  try { Optimize-Volume -DriveLetter $_.DriveLetter -ErrorAction Stop | Out-Null; Write-Output "[OK] Disco $($_.DriveLetter): optimizado" }
  catch { Write-Output "[!!] No se pudo optimizar $($_.DriveLetter):" }
}`, nil)
		if err != nil {
			j.log("[!!] Error al optimizar discos: " + err.Error())
		}
	}
	if sel["storage"] {
		k := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy`
		e1 := runNative(j, "reg", "add", k, "/v", "01", "/t", "REG_DWORD", "/d", "1", "/f")
		e2 := runNative(j, "reg", "add", k, "/v", "2048", "/t", "REG_DWORD", "/d", "1", "/f")
		if e1 != nil || e2 != nil {
			j.log("[!!] No se pudo configurar el Sensor de almacenamiento")
		} else {
			j.log("[OK] Sensor de almacenamiento activado (limpieza automática)")
		}
	}
	if sel["dns"] {
		if err := runNative(j, "ipconfig", "/flushdns"); err != nil {
			j.log("[!!] No se pudo vaciar la caché DNS")
		} else {
			j.log("[OK] Caché DNS vaciada")
		}
	}
	if sel["dismcheck"] {
		j.log("Comprobando integridad del sistema (DISM CheckHealth)...")
		if err := runNative(j, "Dism.exe", "/Online", "/Cleanup-Image", "/CheckHealth"); err != nil {
			j.log("[!!] No se pudo ejecutar la comprobación DISM")
		} else {
			j.log("[OK] Comprobación de integridad realizada")
		}
	}
	j.log("")
	j.log("[OK] OPTIMIZACIÓN COMPLETADA. Se recomienda reiniciar el equipo.")
}

// ------------------------------------------------------------ diagnostico

const psDiag = `
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
[pscustomobject]@{
  equipo   = $cs.Name
  windows  = "$($os.Caption) $($os.Version)"
  cpu      = $cpu.Name.Trim()
  ramTotal = [double]$cs.TotalPhysicalMemory
  ramLibre = [double]($os.FreePhysicalMemory * 1KB)
  horas    = [int]((Get-Date) - $os.LastBootUpTime).TotalHours
  discos   = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
               [pscustomobject]@{ letra=$_.DeviceID; libre=[double]$_.FreeSpace; total=[double]$_.Size } })
  top      = @(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 | ForEach-Object {
               [pscustomobject]@{ nombre=$_.ProcessName; bytes=[double]$_.WorkingSet64 } })
  salud    = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
               [pscustomobject]@{ nombre=$_.FriendlyName; estado="$($_.HealthStatus)" } })
} | ConvertTo-Json -Depth 5 -Compress
`

func runDiagnostico() map[string]interface{} {
	res := map[string]interface{}{}
	out, err := psOutput(psDiag, nil)
	if err != nil {
		res["error"] = err.Error()
	} else {
		var v interface{}
		if json.Unmarshal([]byte(out), &v) == nil {
			res["sistema"] = v
		} else {
			res["error"] = "respuesta inesperada de PowerShell"
		}
	}
	items := scanLimpieza()
	var total int64
	for _, it := range items {
		total += it.Bytes
	}
	res["basura"] = items
	res["basuraTotal"] = total
	return res
}

// ------------------------------------------------------------ arranque

const psStartupDefs = `
$defs = @(
  @{ s='HKLM';   p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';              a='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' },
  @{ s='HKLM32'; p='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';  a='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' },
  @{ s='HKCU';   p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';              a='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
)
`

type startupItem struct {
	Scope   string `json:"scope"`
	Name    string `json:"name"`
	Cmd     string `json:"cmd"`
	Enabled bool   `json:"enabled"`
}

func listStartup() interface{} {
	out, err := psOutput(psStartupDefs+`
$items = @()
foreach ($d in $defs) {
  if (Test-Path $d.p) {
    $k = Get-Item $d.p
    $ap = $null; if (Test-Path $d.a) { $ap = Get-ItemProperty $d.a }
    foreach ($n in $k.GetValueNames()) {
      if (-not $n) { continue }
      $en = $true
      if ($ap) { $v = $ap.$n; if ($v -is [byte[]] -and $v.Length -gt 0 -and (($v[0] -band 1) -eq 1)) { $en = $false } }
      $items += [pscustomobject]@{ scope=$d.s; name=$n; cmd=[string]$k.GetValue($n); enabled=$en }
    }
  }
}
ConvertTo-Json -InputObject @($items) -Compress`, nil)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	var v []startupItem
	if json.Unmarshal([]byte(out), &v) != nil {
		return map[string]string{"error": "respuesta inesperada de PowerShell"}
	}
	return v
}

func setStartupEnabled(scope, name string, enabled bool) error {
	// Solo se permite actuar sobre entradas que existen realmente.
	found := false
	if l, ok := listStartup().([]startupItem); ok {
		for _, it := range l {
			if it.Scope == scope && it.Name == name {
				found = true
			}
		}
	}
	if !found {
		return errors.New("entrada de inicio no encontrada")
	}
	en := "0"
	if enabled {
		en = "1"
	}
	_, err := psOutput(psStartupDefs+`
$d = $defs | Where-Object { $_.s -eq $env:OPT_SCOPE } | Select-Object -First 1
if (-not $d) { throw 'ambito invalido' }
if (-not (Test-Path $d.a)) { New-Item -Path $d.a -Force | Out-Null }
$b = New-Object byte[] 12
if ($env:OPT_EN -eq '1') { $b[0] = 2 } else { $b[0] = 3 }
Set-ItemProperty -Path $d.a -Name $env:OPT_NAME -Value $b -Type Binary -ErrorAction Stop`,
		map[string]string{"OPT_SCOPE": scope, "OPT_NAME": name, "OPT_EN": en})
	return err
}

// ------------------------------------------------------------ programas

const psUninstallDefs = `
$roots = @{
  HKLM   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  HKLM32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  HKCU   = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
}
`

type programa struct {
	ID        string  `json:"id"`
	Nombre    string  `json:"nombre"`
	Version   string  `json:"version"`
	Editor    string  `json:"editor"`
	MB        float64 `json:"mb"`
	Instalado string  `json:"instalado"`
}

func listProgramas() interface{} {
	out, err := psOutput(psUninstallDefs+`
$list = foreach ($h in $roots.Keys) {
  Get-ChildItem -LiteralPath $roots[$h] -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
    if ($p.DisplayName -and $p.UninstallString -and -not $p.SystemComponent -and -not $p.ParentKeyName) {
      [pscustomobject]@{ id="$h|$($_.PSChildName)"; nombre=([string]$p.DisplayName).Trim(); version=[string]$p.DisplayVersion;
        editor=[string]$p.Publisher; mb=$(if ($p.EstimatedSize) { [math]::Round($p.EstimatedSize/1024,1) } else { 0 }); instalado=[string]$p.InstallDate }
    }
  }
}
$list = @($list | Sort-Object nombre -Unique)
ConvertTo-Json -InputObject $list -Compress`, nil)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	var v []programa
	if json.Unmarshal([]byte(out), &v) != nil {
		return map[string]string{"error": "respuesta inesperada de PowerShell"}
	}
	sort.Slice(v, func(a, b int) bool { return strings.ToLower(v[a].Nombre) < strings.ToLower(v[b].Nombre) })
	return v
}

// desinstalar: el cliente solo manda un ID; el comando real se lee del registro aqui.
func desinstalar(id string) (string, error) {
	parts := strings.SplitN(id, "|", 2)
	if len(parts) != 2 || strings.ContainsAny(parts[1], `\/`) {
		return "", errors.New("identificador invalido")
	}
	out, err := psOutput(psUninstallDefs+`
$h, $k = $env:OPT_ID -split '\|', 2
if (-not $roots.ContainsKey($h)) { throw 'ambito invalido' }
$p = Get-ItemProperty -LiteralPath (Join-Path $roots[$h] $k) -ErrorAction Stop
ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ nombre=[string]$p.DisplayName; cmd=[string]$p.UninstallString })`,
		map[string]string{"OPT_ID": id})
	if err != nil {
		return "", err
	}
	var r struct{ Nombre, Cmd string }
	if json.Unmarshal([]byte(out), &r) != nil || strings.TrimSpace(r.Cmd) == "" {
		return "", errors.New("no se encontro el desinstalador")
	}
	if err := lanzarDesinstalador(r.Cmd); err != nil {
		return "", err
	}
	return "Desinstalador iniciado para: " + r.Nombre + ". Completa su ventana si aparece.", nil
}

// ------------------------------------------------------------ usuarios

type usuario struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func listUsuarios() interface{} {
	out, err := psOutput(`
$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }
$adm = @(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
$u = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { [pscustomobject]@{ name=$_.Name; admin=($adm -contains $_.Name) } })
ConvertTo-Json -InputObject $u -Compress`, nil)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	var v []usuario
	if json.Unmarshal([]byte(out), &v) != nil {
		return map[string]string{"error": "respuesta inesperada de PowerShell"}
	}
	return v
}

func hacerAdmin(user string) (string, error) {
	ok := false
	if l, isList := listUsuarios().([]usuario); isList {
		for _, u := range l {
			if u.Name == user {
				ok = true
				if u.Admin {
					return "'" + user + "' ya es administrador de este equipo.", nil
				}
			}
		}
	}
	if !ok {
		return "", errors.New("el usuario no existe en este equipo")
	}
	_, err := psOutput(`
$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }
Add-LocalGroupMember -Group $g.Name -Member $env:OPT_USER -ErrorAction Stop`, map[string]string{"OPT_USER": user})
	if err != nil {
		return "", err
	}
	return "'" + user + "' ahora es ADMINISTRADOR de este equipo. Cierra sesión y vuelve a entrar para que surta efecto.", nil
}
