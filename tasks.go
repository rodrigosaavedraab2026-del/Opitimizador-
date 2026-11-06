//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func runtimeCPUs() int { return runtime.NumCPU() }

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

// vaciarCarpeta borra el CONTENIDO de una carpeta; los archivos en uso se omiten.
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

func carpetaSegura(dir string) bool {
	d := filepath.Clean(dir)
	if len(d) < 8 || d == filepath.VolumeName(d)+string(filepath.Separator) {
		return false
	}
	low := strings.ToLower(d)
	for _, bad := range []string{"documents", "documentos", "desktop", "escritorio", "pictures", "imagenes", "imágenes", "downloads", "descargas", "videos", "music", "música"} {
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
	Group   string `json:"group"`
	Bytes   int64  `json:"bytes"`
	Default bool   `json:"default"`
	Manual  bool   `json:"manual"`
	paths   []string
	files   []string
	stopSvc []string
}

func catalogoLimpieza() []*limpItem {
	local := env("LOCALAPPDATA")
	win := env("WINDIR")
	if win == "" {
		win = env("SystemRoot")
	}
	pd := env("ProgramData")
	var firefox []string
	if local != "" {
		profs, _ := filepath.Glob(filepath.Join(local, "Mozilla", "Firefox", "Profiles", "*"))
		for _, p := range profs {
			firefox = append(firefox, filepath.Join(p, "cache2"), filepath.Join(p, "startupCache"))
		}
	}
	return []*limpItem{
		{ID: "temp_user", Group: "Sistema", Name: "Temporales del usuario", Desc: "Carpeta %TEMP%", Default: true, paths: []string{env("TEMP")}},
		{ID: "temp_win", Group: "Sistema", Name: "Temporales de Windows", Desc: "C:\\Windows\\Temp", Default: true, paths: []string{join(win, "Temp")}},
		{ID: "prefetch", Group: "Sistema", Name: "Prefetch", Desc: "Datos de precarga de programas", Default: true, paths: []string{join(win, "Prefetch")}},
		{ID: "wu_cache", Group: "Sistema", Name: "Caché de Windows Update", Desc: "Descargas de actualizaciones ya instaladas (se detiene el servicio un momento)", Default: true,
			paths: []string{join(win, "SoftwareDistribution", "Download")}, stopSvc: []string{"wuauserv", "bits"}},
		{ID: "delivery", Group: "Sistema", Name: "Optimización de distribución", Desc: "Caché de Delivery Optimization", Default: true,
			paths: []string{join(win, `ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache`)}, stopSvc: []string{"dosvc"}},
		{ID: "wer", Group: "Sistema", Name: "Informes de errores de Windows", Desc: "Carpeta WER y volcados de aplicaciones", Default: true,
			paths: []string{join(pd, `Microsoft\Windows\WER\ReportArchive`), join(pd, `Microsoft\Windows\WER\ReportQueue`), join(local, "CrashDumps")}},
		{ID: "thumbs", Group: "Sistema", Name: "Caché de miniaturas", Desc: "thumbcache_*.db del Explorador", Default: true, files: []string{join(local, `Microsoft\Windows\Explorer\thumbcache_*.db`)}},
		{ID: "dx", Group: "Sistema", Name: "Caché de shaders DirectX", Desc: "Se regenera sola al abrir juegos", Default: false, paths: []string{join(local, "D3DSCache")}},
		{ID: "chrome", Group: "Navegadores", Name: "Caché de Chrome", Desc: "Solo caché, no contraseñas ni historial (cierra Chrome)", Default: true,
			paths: perfilesChromium(join(local, `Google\Chrome\User Data`), "Cache", "Code Cache", "GPUCache")},
		{ID: "edge", Group: "Navegadores", Name: "Caché de Edge", Desc: "Solo caché, no contraseñas ni historial", Default: true,
			paths: perfilesChromium(join(local, `Microsoft\Edge\User Data`), "Cache", "Code Cache", "GPUCache")},
		{ID: "brave", Group: "Navegadores", Name: "Caché de Brave", Desc: "Solo caché, no contraseñas ni historial", Default: true,
			paths: perfilesChromium(join(local, `BraveSoftware\Brave-Browser\User Data`), "Cache", "Code Cache", "GPUCache")},
		{ID: "firefox", Group: "Navegadores", Name: "Caché de Firefox", Desc: "Solo caché, no contraseñas ni historial", Default: true, paths: firefox},
		{ID: "recycle", Group: "Acciones", Name: "Papelera de reciclaje", Desc: "Vacía la papelera de todas las unidades", Default: true, Manual: true},
		{ID: "dism", Group: "Acciones", Name: "Limpieza profunda de componentes (DISM)", Desc: "StartComponentCleanup. Tarda varios minutos", Default: false, Manual: true},
		{ID: "dns", Group: "Acciones", Name: "Vaciar caché DNS", Desc: "ipconfig /flushdns", Default: true, Manual: true},
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
		if !sel[it.ID] || j.cancelled() {
			continue
		}
		switch it.ID {
		case "recycle":
			if err := emptyRecycleBin(); err != nil {
				j.log("[!!] Papelera: " + err.Error())
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
			do := func() {
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
			}
			if len(it.stopSvc) > 0 {
				withServiceStopped(it.stopSvc, do)
			} else {
				do()
			}
			total += lib
			j.log(fmt.Sprintf("[OK] %-42s liberado: %s", it.Name, fmtSize(lib)))
		}
	}
	j.log("")
	j.log("[OK] LIMPIEZA COMPLETADA. Espacio liberado (aprox.): " + fmtSize(total))
}

// ------------------------------------------------------------ optimizar

var reGUID = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func activarPlanEnergia(j *Job) {
	list, _ := nativeOutput(20e9, "powercfg", "/list")
	if m := regexp.MustCompile(`(?i)8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`).FindString(list); m != "" {
		if runNative(j, "powercfg", "/setactive", m) == nil {
			j.log("[OK] Plan 'Alto rendimiento' activado")
			return
		}
	}
	// No existe: se crea una copia del plan 'Máximo rendimiento' y se activa SU nuevo GUID.
	out, err := nativeOutput(20e9, "powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61")
	if g := reGUID.FindString(out); err == nil && g != "" {
		if runNative(j, "powercfg", "/setactive", g) == nil {
			j.log("[OK] Plan 'Máximo rendimiento' creado y activado")
			return
		}
	}
	j.log("[!!] Este equipo no ofrece planes de alto rendimiento (suele pasar en portátiles con Modern Standby). No se cambió nada.")
}

func setDword(root registry.Key, path, name string, v uint32) error {
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, v)
}

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
			j.log("[!!] No se pudo crear el punto de restauración (Windows permite uno cada 24 h o la protección del sistema está desactivada)")
		} else {
			j.log("[OK] Punto de restauración creado")
		}
	}
	if sel["power"] {
		activarPlanEnergia(j)
	}
	if sel["trim"] {
		j.log("Optimizando discos (TRIM en SSD / desfragmentación en HDD)...")
		for _, d := range fixedDisks() {
			if j.cancelled() {
				break
			}
			if !strings.EqualFold(d.FS, "NTFS") {
				continue
			}
			if err := runNative(j, "defrag.exe", d.Letter, "/O"); err != nil {
				j.log("[!!] No se pudo optimizar " + d.Letter + " (" + err.Error() + ")")
			} else {
				j.log("[OK] Disco " + d.Letter + " optimizado")
			}
		}
	}
	if sel["storage"] {
		k := `SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy`
		e1 := setDword(registry.CURRENT_USER, k, "01", 1)
		e2 := setDword(registry.CURRENT_USER, k, "2048", 1)
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
	if sel["hibernate"] {
		if err := runNative(j, "powercfg", "/hibernate", "off"); err != nil {
			j.log("[!!] No se pudo desactivar la hibernación")
		} else {
			j.log("[OK] Hibernación desactivada (se libera el archivo hiberfil.sys)")
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

// ------------------------------------------------------------ reparacion

func runReparar(j *Job, ids []string) {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	j.log("== REPARACIÓN DEL SISTEMA ==")
	steps := []struct {
		id, title string
		exe       string
		args      []string
	}{
		{"dism_scan", "DISM: buscar daños en la imagen de Windows", "Dism.exe", []string{"/Online", "/Cleanup-Image", "/ScanHealth"}},
		{"dism_restore", "DISM: reparar la imagen de Windows (necesita Internet)", "Dism.exe", []string{"/Online", "/Cleanup-Image", "/RestoreHealth"}},
		{"sfc", "SFC: verificar y reparar archivos del sistema", "sfc.exe", []string{"/scannow"}},
		{"chkdsk", "CHKDSK: comprobar el disco del sistema (sin reiniciar)", "chkdsk.exe", []string{strings.TrimSuffix(env("SystemDrive"), `\`), "/scan"}},
	}
	for _, s := range steps {
		if !sel[s.id] || j.cancelled() {
			continue
		}
		j.log("")
		j.log(">> " + s.title)
		if err := runNative(j, s.exe, s.args...); err != nil {
			if j.cancelled() {
				j.log("[!!] Cancelado por el usuario")
				return
			}
			j.log("[!!] " + s.exe + " terminó con aviso: " + err.Error() + " (revisa el detalle de arriba)")
		} else {
			j.log("[OK] " + s.title + ": terminado")
		}
	}
	j.log("")
	j.log("[OK] PROCESO FINALIZADO")
}

// ------------------------------------------------------------ arranque

type startupDef struct {
	Scope, Run, Approved string
	Root, ARoot          registry.Key
	Folder               string
}

func startupDefs() []startupDef {
	const base = `SOFTWARE\Microsoft\Windows\CurrentVersion`
	return []startupDef{
		{Scope: "HKLM", Root: registry.LOCAL_MACHINE, Run: base + `\Run`, ARoot: registry.LOCAL_MACHINE, Approved: base + `\Explorer\StartupApproved\Run`},
		{Scope: "HKLM32", Root: registry.LOCAL_MACHINE, Run: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, ARoot: registry.LOCAL_MACHINE, Approved: base + `\Explorer\StartupApproved\Run32`},
		{Scope: "HKCU", Root: registry.CURRENT_USER, Run: base + `\Run`, ARoot: registry.CURRENT_USER, Approved: base + `\Explorer\StartupApproved\Run`},
		{Scope: "CARPETA_USUARIO", ARoot: registry.CURRENT_USER, Approved: base + `\Explorer\StartupApproved\StartupFolder`,
			Folder: join(env("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
		{Scope: "CARPETA_COMUN", ARoot: registry.LOCAL_MACHINE, Approved: base + `\Explorer\StartupApproved\StartupFolder`,
			Folder: join(env("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
	}
}

type startupItem struct {
	Scope   string `json:"scope"`
	Name    string `json:"name"`
	Cmd     string `json:"cmd"`
	Enabled bool   `json:"enabled"`
}

func approvedEnabled(d startupDef, name string) bool {
	k, err := registry.OpenKey(d.ARoot, d.Approved, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue(name)
	if err != nil || len(b) == 0 {
		return true
	}
	return b[0]&1 == 0 // 02/06 = activo, 03/07 = desactivado
}

func listStartup() []startupItem {
	out := []startupItem{}
	for _, d := range startupDefs() {
		if d.Folder != "" {
			ents, _ := os.ReadDir(d.Folder)
			for _, e := range ents {
				if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
					continue
				}
				out = append(out, startupItem{Scope: d.Scope, Name: e.Name(), Cmd: filepath.Join(d.Folder, e.Name()), Enabled: approvedEnabled(d, e.Name())})
			}
			continue
		}
		k, err := registry.OpenKey(d.Root, d.Run, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			if n == "" {
				continue
			}
			v, _, _ := k.GetStringValue(n)
			out = append(out, startupItem{Scope: d.Scope, Name: n, Cmd: v, Enabled: approvedEnabled(d, n)})
		}
		k.Close()
	}
	return out
}

func setStartupEnabled(scope, name string, enabled bool) error {
	found := false
	for _, it := range listStartup() {
		if it.Scope == scope && it.Name == name {
			found = true
		}
	}
	if !found {
		return errors.New("entrada de inicio no encontrada")
	}
	for _, d := range startupDefs() {
		if d.Scope != scope {
			continue
		}
		k, _, err := registry.CreateKey(d.ARoot, d.Approved, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		b := make([]byte, 12)
		if enabled {
			b[0] = 2
		} else {
			b[0] = 3
		}
		return k.SetBinaryValue(name, b)
	}
	return errors.New("ámbito inválido")
}

// ------------------------------------------------------------ programas

type programa struct {
	ID        string  `json:"id"`
	Nombre    string  `json:"nombre"`
	Version   string  `json:"version"`
	Editor    string  `json:"editor"`
	MB        float64 `json:"mb"`
	Instalado string  `json:"instalado"`
}

const uninstBase = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

var uninstRoots = []struct {
	Tag  string
	Root registry.Key
	Path string
}{
	{"HKLM", registry.LOCAL_MACHINE, uninstBase},
	{"HKLM32", registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{"HKCU", registry.CURRENT_USER, uninstBase},
}

func listProgramas() []programa {
	seen := map[string]bool{}
	out := []programa{}
	for _, r := range uninstRoots {
		for _, sk := range regSubkeys(r.Root, r.Path) {
			p := r.Path + `\` + sk
			name := strings.TrimSpace(regStr(r.Root, p, "DisplayName"))
			un := regStr(r.Root, p, "UninstallString")
			if name == "" || un == "" || seen[strings.ToLower(name)] {
				continue
			}
			if v, ok := regDword(r.Root, p, "SystemComponent"); ok && v == 1 {
				continue
			}
			if regStr(r.Root, p, "ParentKeyName") != "" {
				continue
			}
			size, _ := regDword(r.Root, p, "EstimatedSize")
			seen[strings.ToLower(name)] = true
			out = append(out, programa{ID: r.Tag + "|" + sk, Nombre: name, Version: regStr(r.Root, p, "DisplayVersion"),
				Editor: regStr(r.Root, p, "Publisher"), MB: float64(size) / 1024, Instalado: regStr(r.Root, p, "InstallDate")})
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Nombre) < strings.ToLower(out[j].Nombre) })
	return out
}

func desinstalar(id string) (string, error) {
	parts := strings.SplitN(id, "|", 2)
	if len(parts) != 2 || strings.ContainsAny(parts[1], `\/`) {
		return "", errors.New("identificador inválido")
	}
	for _, r := range uninstRoots {
		if r.Tag != parts[0] {
			continue
		}
		p := r.Path + `\` + parts[1]
		cmd := strings.TrimSpace(regStr(r.Root, p, "UninstallString"))
		name := regStr(r.Root, p, "DisplayName")
		if cmd == "" {
			return "", errors.New("no se encontró el desinstalador de este programa")
		}
		if err := lanzarDesinstalador(cmd); err != nil {
			return "", err
		}
		return "Desinstalador iniciado para: " + name + ". Completa su ventana si aparece.", nil
	}
	return "", errors.New("origen inválido")
}

// ------------------------------------------------------------ apps de la Tienda (PowerShell)

type appx struct {
	ID      string `json:"id"`
	Nombre  string `json:"nombre"`
	Editor  string `json:"editor"`
	Version string `json:"version"`
}

var appxProtegidas = []string{"microsoft.vclibs", "microsoft.ui.xaml", "microsoft.net", "microsoft.windowsstore", "microsoft.desktopappinstaller",
	"microsoft.sechealthui", "microsoft.windows.", "microsoftwindows.", "windows.", "microsoft.windowsappruntime", "microsoft.services.store",
	"microsoft.storepurchaseapp", "microsoft.aad", "microsoft.accountscontrol", "microsoft.lockapp", "microsoft.creddialoghost", "microsoft.win32webviewhost",
	"microsoft.bioenrollment", "microsoft.asynctextservice", "microsoft.microsoftedge", "nvidia", "realtek", "intel", "amd", "microsoft.hevc", "microsoft.heif", "microsoft.webp", "microsoft.vp9"}

func listAppx() ([]appx, error) {
	out, err := psOutput(`
$l = @(Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and $_.SignatureKind -ne 'System' } | ForEach-Object {
  [pscustomobject]@{ id=$_.PackageFullName; nombre=$_.Name; editor=([string]$_.Publisher -replace '^CN=([^,]+).*','$1'); version=[string]$_.Version } } | Sort-Object nombre)
ConvertTo-Json -InputObject $l -Compress`, nil)
	if err != nil {
		return nil, err
	}
	var all []appx
	if out == "" || json.Unmarshal([]byte(out), &all) != nil {
		return []appx{}, nil
	}
	res := []appx{}
next:
	for _, a := range all {
		low := strings.ToLower(a.Nombre)
		for _, p := range appxProtegidas {
			if strings.HasPrefix(low, p) {
				continue next
			}
		}
		res = append(res, a)
	}
	return res, nil
}

func quitarAppx(id string) error {
	l, err := listAppx()
	if err != nil {
		return err
	}
	ok := false
	for _, a := range l {
		if a.ID == id {
			ok = true
		}
	}
	if !ok {
		return errors.New("aplicación no encontrada o protegida")
	}
	_, err = psOutput(`Get-AppxPackage | Where-Object { $_.PackageFullName -eq $env:OPT_ID } | Remove-AppxPackage -ErrorAction Stop`, map[string]string{"OPT_ID": id})
	return err
}

// ------------------------------------------------------------ usuarios (PowerShell)

type usuario struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func listUsuarios() ([]usuario, error) {
	out, err := psOutput(`
$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }
$adm = @(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split '\\')[-1] })
$u = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { [pscustomobject]@{ name=$_.Name; admin=($adm -contains $_.Name) } })
ConvertTo-Json -InputObject $u -Compress`, nil)
	if err != nil {
		return nil, err
	}
	var v []usuario
	if json.Unmarshal([]byte(out), &v) != nil {
		return nil, errors.New("respuesta inesperada de PowerShell")
	}
	return v, nil
}

func hacerAdmin(user string) (string, error) {
	l, err := listUsuarios()
	if err != nil {
		return "", err
	}
	ok := false
	for _, u := range l {
		if u.Name == user {
			ok = true
			if u.Admin {
				return "'" + user + "' ya es administrador de este equipo.", nil
			}
		}
	}
	if !ok {
		return "", errors.New("el usuario no existe en este equipo")
	}
	_, err = psOutput(`
$g = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' }
Add-LocalGroupMember -Group $g.Name -Member $env:OPT_USER -ErrorAction Stop`, map[string]string{"OPT_USER": user})
	if err != nil {
		return "", err
	}
	return "'" + user + "' ahora es ADMINISTRADOR de este equipo. Cierra sesión y vuelve a entrar para que surta efecto.", nil
}
