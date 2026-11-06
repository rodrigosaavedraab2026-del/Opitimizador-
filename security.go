//go:build windows

package main

// Modulo de seguridad DEFENSIVA sobre el propio equipo: auditoria de configuracion,
// busqueda de persistencia, analisis estatico de archivos (nunca se ejecutan) y
// lectura de eventos de seguridad. Cada hallazgo indica que se OBSERVO y que se INFIERE.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ------------------------------------------------------------------ utilidades comunes

func psJSON(script string, envv map[string]string, out interface{}) error {
	s, err := psOutput(script, envv)
	if err != nil {
		return err
	}
	if s == "" {
		return errors.New("PowerShell no devolvió datos")
	}
	return json.Unmarshal([]byte(s), out)
}

var rePct = regexp.MustCompile(`%([A-Za-z0-9_()]+)%`)

func expandPct(s string) string {
	return rePct.ReplaceAllStringFunc(s, func(m string) string {
		if v := os.Getenv(m[1 : len(m)-1]); v != "" {
			return v
		}
		return m
	})
}

// exeDeComando extrae la ruta del ejecutable de una linea de comando del registro/tarea.
func exeDeComando(cmd string) string {
	c := strings.TrimSpace(expandPct(cmd))
	c = strings.TrimPrefix(c, `\??\`)
	if c == "" {
		return ""
	}
	var p string
	if c[0] == '"' {
		if i := strings.Index(c[1:], `"`); i >= 0 {
			p = c[1 : 1+i]
		} else {
			p = c[1:]
		}
	} else if i := strings.Index(strings.ToLower(c), ".exe"); i >= 0 {
		p = c[:i+4]
	} else {
		p = strings.Fields(c)[0]
	}
	p = strings.TrimSpace(p)
	if !strings.ContainsAny(p, `\/`) { // nombre suelto: se busca en System32 y PATH
		win := os.Getenv("WINDIR")
		for _, d := range []string{filepath.Join(win, "System32"), win} {
			if st, err := os.Stat(filepath.Join(d, p)); err == nil && !st.IsDir() {
				return filepath.Join(d, p)
			}
		}
		if lp, err := lookPath(p); err == nil {
			return lp
		}
	}
	return p
}

func lookPath(name string) (string, error) {
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if st, err := os.Stat(filepath.Join(d, name)); err == nil && !st.IsDir() {
			return filepath.Join(d, name), nil
		}
	}
	return "", errors.New("no encontrado")
}

var rutasRiesgo = []string{`\temp\`, `\tmp\`, `\downloads\`, `\descargas\`, `\users\public\`, `\$recycle.bin\`, `\appdata\local\temp\`, `\windows\temp\`}

func enRutaRiesgo(p string) bool {
	low := strings.ToLower(p)
	for _, r := range rutasRiesgo {
		if strings.Contains(low, r) {
			return true
		}
	}
	return false
}

var lolbins = []string{"powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec"}
var reArgsSospechosos = regexp.MustCompile(`(?i)(-enc\b|-encodedcommand|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|https?://|urlcache|\\appdata\\|\\temp\\)`)

type sigInfo struct {
	Status string `json:"status"`
	Signer string `json:"signer"`
}

// firmas: comprueba Authenticode de varios archivos con una sola llamada a PowerShell.
func firmas(paths []string) map[string]sigInfo {
	res := map[string]sigInfo{}
	if len(paths) == 0 {
		return res
	}
	if len(paths) > 150 {
		paths = paths[:150]
	}
	b, _ := json.Marshal(paths)
	var out []struct{ Path, Status, Signer string }
	err := psJSON(`
$paths = $env:OPT_PATHS | ConvertFrom-Json
$res = @(foreach ($p in @($paths)) { try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
  [pscustomobject]@{ Path=$p; Status=[string]$s.Status; Signer=[string]$s.SignerCertificate.Subject } } catch { [pscustomobject]@{ Path=$p; Status='Error'; Signer='' } } })
ConvertTo-Json -InputObject $res -Compress`, map[string]string{"OPT_PATHS": string(b)}, &out)
	if err != nil {
		return res
	}
	for _, o := range out {
		res[strings.ToLower(o.Path)] = sigInfo{o.Status, o.Signer}
	}
	return res
}

func sha256Archivo(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, _ := f.Stat(); st != nil && st.Size() > 200<<20 {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ================================================================== 1) AUDITORIA

type check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | bad | info
	Detail string `json:"detail"`
	Fix    string `json:"fix"` // etiqueta del boton de correccion ("" = sin correccion automatica)
}

func lm(path, name string) (uint32, bool) { return regDword(registry.LOCAL_MACHINE, path, name) }

func ejecutarAuditoria() []check {
	var checks []check
	add := func(id, name, st, detail, fix string) { checks = append(checks, check{id, name, st, detail, fix}) }

	var ps struct {
		Defender *struct {
			RT     bool `json:"rt"`
			AV     bool `json:"av"`
			SigAge int  `json:"sigAge"`
			Tamper bool `json:"tamper"`
		} `json:"defender"`
		BitLocker *string `json:"bitlocker"`
		HotfixDay *int    `json:"hotfixDays"`
		Guest     *bool   `json:"guest"`
		Admin     *bool   `json:"admin"`
	}
	psErr := psJSON(`
$r = @{}
try { $m = Get-MpComputerStatus; $r.defender = @{ rt=[bool]$m.RealTimeProtectionEnabled; av=[bool]$m.AntivirusEnabled; sigAge=[int]$m.AntivirusSignatureAge; tamper=[bool]$m.IsTamperProtected } } catch { $r.defender = $null }
try { $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; $r.bitlocker = [string]$b.ProtectionStatus } catch { $r.bitlocker = $null }
try { $h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; $r.hotfixDays = [int]((Get-Date) - $h.InstalledOn).TotalDays } catch { $r.hotfixDays = $null }
try { $u = @(Get-LocalUser); $g = $u | Where-Object { $_.SID.Value -like '*-501' }; $a = $u | Where-Object { $_.SID.Value -like '*-500' }
  $r.guest = [bool]$g.Enabled; $r.admin = [bool]$a.Enabled } catch { }
$r | ConvertTo-Json -Compress -Depth 4`, nil, &ps)

	// Defender
	if ps.Defender == nil {
		det := "No se pudo consultar Microsoft Defender (¿hay otro antivirus instalado?)."
		if psErr != nil {
			det += " " + psErr.Error()
		}
		add("defender", "Antivirus (Microsoft Defender)", "info", det, "")
	} else if !ps.Defender.RT {
		add("defender", "Protección en tiempo real", "bad", "Desactivada. El equipo no analiza archivos al abrirlos.", "Activar")
	} else if ps.Defender.SigAge > 7 {
		add("defender", "Antivirus (Microsoft Defender)", "warn", fmt.Sprintf("Protección activa, pero las firmas tienen %d días.", ps.Defender.SigAge), "")
	} else {
		d := fmt.Sprintf("Activo; firmas de hace %d día(s).", ps.Defender.SigAge)
		if ps.Defender.Tamper {
			d += " Protección contra alteraciones activada."
		}
		add("defender", "Antivirus (Microsoft Defender)", "ok", d, "")
	}

	// Firewall
	fw := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	var off []string
	for _, p := range [][2]string{{"DomainProfile", "Dominio"}, {"StandardProfile", "Privado"}, {"PublicProfile", "Público"}} {
		if v, ok := lm(fw+p[0], "EnableFirewall"); ok && v == 0 {
			off = append(off, p[1])
		}
	}
	if len(off) > 0 {
		add("firewall", "Firewall de Windows", "bad", "Desactivado en: "+strings.Join(off, ", ")+".", "Activar")
	} else {
		add("firewall", "Firewall de Windows", "ok", "Activado en los tres perfiles.", "")
	}

	// UAC
	sys := `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	if v, ok := lm(sys, "EnableLUA"); ok && v == 0 {
		add("uac", "Control de cuentas de usuario (UAC)", "bad", "Desactivado: los programas pueden elevarse sin avisar.", "Activar")
	} else if c, ok := lm(sys, "ConsentPromptBehaviorAdmin"); ok && c == 0 {
		add("uac", "Control de cuentas de usuario (UAC)", "warn", "Activo pero sin pedir confirmación a administradores.", "")
	} else {
		add("uac", "Control de cuentas de usuario (UAC)", "ok", "Activado.", "")
	}

	// SMBv1
	if v, ok := lm(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok && v == 1 {
		add("smb1", "Protocolo SMBv1", "bad", "Habilitado. Es un protocolo obsoleto usado por gusanos como WannaCry.", "Desactivar")
	} else if ok {
		add("smb1", "Protocolo SMBv1", "ok", "Desactivado.", "")
	} else {
		add("smb1", "Protocolo SMBv1", "info", "Sin configuración explícita; Windows moderno lo trae desactivado.", "Desactivar")
	}

	// RDP
	if v, ok := lm(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); ok && v == 0 {
		nla, _ := lm(`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
		d := "Escritorio remoto habilitado."
		if nla == 0 {
			d += " Sin autenticación de nivel de red (NLA)."
		}
		add("rdp", "Escritorio remoto (RDP)", "warn", d+" Desactívalo si no lo usas.", "Desactivar")
	} else {
		add("rdp", "Escritorio remoto (RDP)", "ok", "Deshabilitado.", "")
	}

	// Autorun
	if v, ok := lm(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun"); ok && v == 255 {
		add("autorun", "Ejecución automática de unidades", "ok", "Desactivada para todos los tipos de unidad.", "")
	} else {
		add("autorun", "Ejecución automática de unidades", "warn", "No está bloqueada por directiva; un USB podría ejecutar contenido automáticamente.", "Bloquear")
	}

	// Secure Boot
	if v, ok := lm(`SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled"); ok && v == 1 {
		add("secureboot", "Arranque seguro (Secure Boot)", "ok", "Activado.", "")
	} else if ok {
		add("secureboot", "Arranque seguro (Secure Boot)", "warn", "Desactivado. Se cambia en la BIOS/UEFI.", "")
	} else {
		add("secureboot", "Arranque seguro (Secure Boot)", "info", "No disponible (BIOS clásica).", "")
	}

	// BitLocker
	switch {
	case ps.BitLocker == nil:
		add("bitlocker", "Cifrado de disco (BitLocker)", "info", "No disponible o sin información (edición Home/otro cifrado).", "")
	case strings.EqualFold(*ps.BitLocker, "On"):
		add("bitlocker", "Cifrado de disco (BitLocker)", "ok", "El disco del sistema está cifrado.", "")
	default:
		add("bitlocker", "Cifrado de disco (BitLocker)", "warn", "El disco del sistema no está cifrado: si roban el equipo, los datos son legibles.", "")
	}

	// Actualizaciones
	if v, ok := lm(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate"); ok && v == 1 {
		add("wu", "Actualizaciones automáticas", "bad", "Desactivadas por directiva.", "Activar")
	} else if ps.HotfixDay != nil && *ps.HotfixDay > 60 {
		add("wu", "Actualizaciones de Windows", "warn", fmt.Sprintf("La última actualización instalada es de hace %d días.", *ps.HotfixDay), "")
	} else if ps.HotfixDay != nil {
		add("wu", "Actualizaciones de Windows", "ok", fmt.Sprintf("Última actualización hace %d día(s).", *ps.HotfixDay), "")
	} else {
		add("wu", "Actualizaciones de Windows", "info", "No se pudo determinar la fecha de la última actualización.", "")
	}

	// Cuentas
	if ps.Guest != nil && *ps.Guest {
		add("guest", "Cuenta Invitado", "bad", "Habilitada. Permite acceso sin contraseña personal.", "Deshabilitar")
	} else if ps.Guest != nil {
		add("guest", "Cuenta Invitado", "ok", "Deshabilitada.", "")
	}
	if ps.Admin != nil && *ps.Admin {
		add("builtinadmin", "Administrador integrado", "warn", "La cuenta «Administrador» integrada está habilitada; es un objetivo habitual de ataques.", "")
	}
	return checks
}

func corregirAuditoria(id string) (string, error) {
	setLM := func(path, name string, v uint32) error { return setDword(registry.LOCAL_MACHINE, path, name, v) }
	switch id {
	case "firewall":
		out, err := nativeOutput(30*time.Second, "netsh", "advfirewall", "set", "allprofiles", "state", "on")
		if err != nil {
			return "", fmt.Errorf("netsh: %s", strings.TrimSpace(out))
		}
		return "Firewall activado en todos los perfiles.", nil
	case "uac":
		if err := setLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", 1); err != nil {
			return "", err
		}
		return "UAC activado. Se aplica al reiniciar.", nil
	case "smb1":
		if err := setLM(`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1", 0); err != nil {
			return "", err
		}
		return "SMBv1 desactivado. Se aplica al reiniciar el servicio o el equipo.", nil
	case "rdp":
		if err := setLM(`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections", 1); err != nil {
			return "", err
		}
		return "Escritorio remoto desactivado.", nil
	case "autorun":
		if err := setLM(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun", 255); err != nil {
			return "", err
		}
		return "Ejecución automática bloqueada.", nil
	case "wu":
		if err := setLM(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate", 0); err != nil {
			return "", err
		}
		return "Actualizaciones automáticas permitidas.", nil
	case "defender":
		if _, err := psOutput(`Set-MpPreference -DisableRealtimeMonitoring $false`, nil); err != nil {
			return "", fmt.Errorf("%v (puede estar bloqueado por la Protección contra alteraciones o por otro antivirus)", err)
		}
		return "Protección en tiempo real activada.", nil
	case "guest":
		if _, err := psOutput(`Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser -ErrorAction Stop`, nil); err != nil {
			return "", err
		}
		return "Cuenta Invitado deshabilitada.", nil
	}
	return "", errors.New("corrección no disponible")
}

// ================================================================== 2) PERSISTENCIA

type hallazgo struct {
	Tipo    string   `json:"tipo"` // inicio | tarea | servicio | red
	Nombre  string   `json:"nombre"`
	Detalle string   `json:"detalle"`
	Ruta    string   `json:"ruta"`
	SHA256  string   `json:"sha256"`
	Firma   string   `json:"firma"`
	Score   int      `json:"score"`
	Nivel   string   `json:"nivel"`
	Motivos []string `json:"motivos"`
	Scope   string   `json:"scope,omitempty"` // para desactivar elementos de inicio
	Tarea   string   `json:"tarea,omitempty"`
}

func nivelDe(score int) string {
	switch {
	case score >= 5:
		return "alto"
	case score >= 2:
		return "medio"
	}
	return "bajo"
}

type conexion struct {
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remoto  string `json:"remoto"`
	Estado  string `json:"estado"`
	PID     uint32 `json:"pid"`
	Proceso string `json:"proceso"`
	Ruta    string `json:"ruta"`
	Score   int    `json:"score"`
	Nivel   string `json:"nivel"`
	Motivo  string `json:"motivo"`
}

type persistResult struct {
	Items      []hallazgo `json:"items"`
	Conexiones []conexion `json:"conexiones"`
	Notas      []string   `json:"notas"`
}

var (
	tareaMu       sync.Mutex
	tareasValidas = map[string]bool{}
)

func buscarPersistencia(j *Job) persistResult {
	res := persistResult{Items: []hallazgo{}, Conexiones: []conexion{}}
	win := strings.ToLower(os.Getenv("WINDIR"))
	var items []*hallazgo
	toCheck := map[string]bool{}

	eval := func(h *hallazgo, cmd string, firmar bool) {
		h.Ruta = exeDeComando(cmd)
		if h.Ruta == "" {
			return
		}
		if st, err := os.Stat(h.Ruta); err != nil || st.IsDir() {
			h.Score += 2
			h.Motivos = append(h.Motivos, "El archivo al que apunta no existe (entrada huérfana o eliminada).")
		} else {
			if firmar {
				toCheck[h.Ruta] = true
			}
			h.SHA256 = sha256Archivo(h.Ruta)
		}
		if enRutaRiesgo(h.Ruta) {
			h.Score += 3
			h.Motivos = append(h.Motivos, "Se ejecuta desde una carpeta temporal o de descargas.")
		}
		low := strings.ToLower(filepathBase(h.Ruta))
		for _, l := range lolbins {
			if strings.Contains(low, l) && reArgsSospechosos.MatchString(cmd) {
				h.Score += 3
				h.Motivos = append(h.Motivos, "Usa un intérprete de Windows con argumentos típicos de descarga u ofuscación.")
				break
			}
		}
		items = append(items, h)
	}

	j.log("Revisando programas de inicio...")
	for _, it := range listStartup() {
		if !it.Enabled {
			continue
		}
		h := &hallazgo{Tipo: "inicio", Nombre: it.Name, Detalle: it.Cmd, Scope: it.Scope}
		eval(h, it.Cmd, true)
	}

	j.log("Revisando servicios de arranque automático...")
	for _, sk := range regSubkeys(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`) {
		base := `SYSTEM\CurrentControlSet\Services\` + sk
		st, ok := lm(base, "Start")
		ty, _ := lm(base, "Type")
		if !ok || st != 2 || ty&0x30 == 0 {
			continue
		}
		img := regStr(registry.LOCAL_MACHINE, base, "ImagePath")
		if strings.Contains(strings.ToLower(img), "svchost.exe") {
			if dll := regStr(registry.LOCAL_MACHINE, base+`\Parameters`, "ServiceDll"); dll != "" {
				img = dll
			} else {
				continue
			}
		}
		if img == "" {
			continue
		}
		low := strings.ToLower(exeDeComando(img))
		enWindows := win != "" && strings.HasPrefix(low, win+`\`)
		h := &hallazgo{Tipo: "servicio", Nombre: sk, Detalle: img}
		eval(h, img, !enWindows)
		if enWindows && h.Score == 0 { // servicios del sistema sin señales: no se listan
			items = items[:len(items)-1]
		}
	}

	j.log("Revisando tareas programadas...")
	var tareas []struct{ Name, Path, Exe, Args, Author string }
	if err := psJSON(`
$l = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $a = @($_.Actions)[0]; if ($a -and $a.Execute) { [pscustomobject]@{ Name=$_.TaskName; Path=$_.TaskPath; Exe=[string]$a.Execute; Args=[string]$a.Arguments; Author=[string]$_.Principal.UserId } } })
ConvertTo-Json -InputObject $l -Compress`, nil, &tareas); err != nil {
		res.Notas = append(res.Notas, "No se pudieron leer las tareas programadas: "+err.Error())
	}
	tareaMu.Lock()
	tareasValidas = map[string]bool{}
	for _, t := range tareas {
		cmd := t.Exe + " " + t.Args
		h := &hallazgo{Tipo: "tarea", Nombre: t.Name, Detalle: strings.TrimSpace(cmd), Tarea: t.Path + t.Name}
		tareasValidas[t.Path+t.Name] = true
		eval(h, `"`+strings.Trim(expandPct(t.Exe), `"`)+`" `+t.Args, true)
	}
	tareaMu.Unlock()

	j.log("Comprobando firmas digitales...")
	var lista []string
	for p := range toCheck {
		lista = append(lista, p)
	}
	sort.Strings(lista)
	sigs := firmas(lista)
	if len(lista) > 0 && len(sigs) == 0 {
		res.Notas = append(res.Notas, "No se pudo comprobar la firma digital de los archivos (PowerShell no disponible).")
	}
	for _, h := range items {
		if s, ok := sigs[strings.ToLower(h.Ruta)]; ok {
			h.Firma = s.Status
			switch s.Status {
			case "Valid":
			case "NotSigned":
				h.Score++
				h.Motivos = append(h.Motivos, "Sin firma digital.")
			case "Error":
			default:
				h.Score += 4
				h.Motivos = append(h.Motivos, "La firma digital no es válida ("+s.Status+").")
			}
			if s.Status == "Valid" {
				h.Motivos = append(h.Motivos, "Firma válida: "+nombreFirmante(s.Signer))
			}
		}
		h.Nivel = nivelDe(h.Score)
		if h.Motivos == nil {
			h.Motivos = []string{}
		}
		setAllowed([]string{h.Ruta})
	}
	sort.SliceStable(items, func(a, b int) bool { return items[a].Score > items[b].Score })
	for _, h := range items {
		res.Items = append(res.Items, *h)
	}

	j.log("Leyendo conexiones de red activas...")
	res.Conexiones = listarConexiones()
	j.log(fmt.Sprintf("[OK] %d elementos de persistencia y %d conexiones revisados.", len(res.Items), len(res.Conexiones)))
	return res
}

func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func nombreFirmante(subj string) string {
	for _, part := range strings.Split(subj, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.Trim(part[3:], `"`)
		}
	}
	return subj
}

func desactivarTarea(full string) error {
	tareaMu.Lock()
	ok := tareasValidas[full]
	tareaMu.Unlock()
	if !ok {
		return errors.New("tarea no encontrada (vuelve a analizar)")
	}
	i := strings.LastIndex(full, `\`)
	_, err := psOutput(`Disable-ScheduledTask -TaskPath $env:OPT_PATH -TaskName $env:OPT_NAME -ErrorAction Stop | Out-Null`,
		map[string]string{"OPT_PATH": full[:i+1], "OPT_NAME": full[i+1:]})
	return err
}

// ---- conexiones TCP con su proceso (GetExtendedTcpTable)

var pGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

type tcpRow4 struct{ State, LocalAddr, LocalPort, RemoteAddr, RemotePort, PID uint32 }
type tcpRow6 struct {
	LocalAddr   [16]byte
	LocalScope  uint32
	LocalPort   uint32
	RemoteAddr  [16]byte
	RemoteScope uint32
	RemotePort  uint32
	State, PID  uint32
}

var estadosTCP = map[uint32]string{1: "Cerrada", 2: "Escuchando", 3: "SYN enviado", 4: "SYN recibido", 5: "Conectada", 6: "FIN espera 1", 7: "FIN espera 2", 8: "Cierre", 9: "Cerrando", 10: "Último ACK", 11: "Tiempo de espera", 12: "Eliminada"}

func tablaTCP(af uint32) []byte {
	var size uint32
	for i := 0; i < 5; i++ {
		var p unsafe.Pointer
		var buf []byte
		if size > 0 {
			buf = make([]byte, size)
			p = unsafe.Pointer(&buf[0])
		}
		r, _, _ := pGetExtendedTcpTable.Call(uintptr(p), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), 5 /*TCP_TABLE_OWNER_PID_ALL*/, 0)
		if r == 0 && buf != nil {
			return buf
		}
		if r != 122 && r != 0 { // != ERROR_INSUFFICIENT_BUFFER
			return nil
		}
		size += 4096
	}
	return nil
}

func puertoDe(v uint32) int { return int((v&0xff)<<8 | (v>>8)&0xff) }

func rutaProceso(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func listarConexiones() []conexion {
	procs := snapshotProcs()
	var out []conexion
	rutas := map[uint32]string{}
	nuevo := func(proto, loc, rem string, estado uint32, pid uint32, escuchaTodas bool, remotoPublico bool, remPort int) {
		c := conexion{Proto: proto, Local: loc, Remoto: rem, Estado: estadosTCP[estado], PID: pid}
		if p := procs[pid]; p != nil {
			c.Proceso = p.Name
		}
		if _, ok := rutas[pid]; !ok {
			rutas[pid] = rutaProceso(pid)
		}
		c.Ruta = rutas[pid]
		if c.Ruta != "" && enRutaRiesgo(c.Ruta) {
			c.Score += 3
			c.Motivo = "El proceso se ejecuta desde una carpeta temporal o de descargas."
		}
		if estado == 5 && remotoPublico && c.Ruta != "" && enRutaRiesgo(c.Ruta) {
			c.Score += 2
		}
		if estado == 2 && escuchaTodas && c.Ruta != "" && !strings.HasPrefix(strings.ToLower(c.Ruta), strings.ToLower(os.Getenv("WINDIR"))) && c.Score == 0 {
			c.Motivo = "Acepta conexiones desde la red."
		}
		c.Nivel = nivelDe(c.Score)
		out = append(out, c)
	}
	if b := tablaTCP(2); len(b) >= 4 {
		n := *(*uint32)(unsafe.Pointer(&b[0]))
		rows := unsafe.Slice((*tcpRow4)(unsafe.Pointer(&b[4])), int(n))
		for _, r := range rows {
			la, ra := net.IP([]byte{byte(r.LocalAddr), byte(r.LocalAddr >> 8), byte(r.LocalAddr >> 16), byte(r.LocalAddr >> 24)}),
				net.IP([]byte{byte(r.RemoteAddr), byte(r.RemoteAddr >> 8), byte(r.RemoteAddr >> 16), byte(r.RemoteAddr >> 24)})
			if la.IsLoopback() && (ra.IsLoopback() || r.State == 2) {
				continue
			}
			pub := r.State == 5 && !ra.IsPrivate() && !ra.IsLoopback()
			nuevo("TCP", fmt.Sprintf("%s:%d", la, puertoDe(r.LocalPort)), fmt.Sprintf("%s:%d", ra, puertoDe(r.RemotePort)), r.State, r.PID, la.IsUnspecified(), pub, puertoDe(r.RemotePort))
		}
	}
	if b := tablaTCP(23); len(b) >= 4 {
		n := *(*uint32)(unsafe.Pointer(&b[0]))
		rows := unsafe.Slice((*tcpRow6)(unsafe.Pointer(&b[4])), int(n))
		for _, r := range rows {
			la, ra := net.IP(r.LocalAddr[:]), net.IP(r.RemoteAddr[:])
			if la.IsLoopback() && (ra.IsLoopback() || r.State == 2) {
				continue
			}
			pub := r.State == 5 && !ra.IsPrivate() && !ra.IsLoopback() && !ra.IsLinkLocalUnicast()
			nuevo("TCP6", fmt.Sprintf("[%s]:%d", la, puertoDe(r.LocalPort)), fmt.Sprintf("[%s]:%d", ra, puertoDe(r.RemotePort)), r.State, r.PID, la.IsUnspecified(), pub, puertoDe(r.RemotePort))
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		return out[a].Estado > out[b].Estado
	})
	return out
}

// ================================================================== 3) ANALISIS DE ARCHIVOS

type seccion struct {
	Nombre   string  `json:"nombre"`
	Tam      uint32  `json:"tam"`
	Entropia float64 `json:"entropia"`
	Flags    string  `json:"flags"`
}

type peInfo struct {
	Maquina   string    `json:"maquina"`
	Subsis    string    `json:"subsistema"`
	Compilado string    `json:"compilado"`
	Secciones []seccion `json:"secciones"`
	Importes  int       `json:"importes"`
	APIs      []apiHit  `json:"apis"`
	Overlay   int64     `json:"overlay"`
	Firmada   bool      `json:"firmaIncrustada"`
	ASLR      bool      `json:"aslr"`
	DEP       bool      `json:"dep"`
}

type apiHit struct {
	Categoria string   `json:"categoria"`
	Funciones []string `json:"funciones"`
}

type cadenasInfo struct {
	URLs     []string `json:"urls"`
	IPs      []string `json:"ips"`
	Registro []string `json:"registro"`
	Comandos []string `json:"comandos"`
	Rutas    []string `json:"rutas"`
	Total    int      `json:"total"`
	Muestra  []string `json:"muestra"`
}

type hallazgoArchivo struct {
	Tipo  string `json:"tipo"` // observado | inferido
	Texto string `json:"texto"`
	Peso  int    `json:"peso"`
}

type analisis struct {
	Nombre    string            `json:"nombre"`
	Ruta      string            `json:"ruta"`
	Tam       int64             `json:"tam"`
	SHA256    string            `json:"sha256"`
	SHA1      string            `json:"sha1"`
	MD5       string            `json:"md5"`
	Tipo      string            `json:"tipo"`
	Entropia  float64           `json:"entropia"`
	PE        *peInfo           `json:"pe"`
	Cadenas   cadenasInfo       `json:"cadenas"`
	Firma     *sigInfo          `json:"firma"`
	Score     int               `json:"score"`
	Veredicto string            `json:"veredicto"`
	Hallazgos []hallazgoArchivo `json:"hallazgos"`
	Yara      string            `json:"yara"`
	Truncado  bool              `json:"truncado"`
	Subido    bool              `json:"subido"`
}

var apisSospechosas = map[string][]string{
	"Inyección en procesos":    {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtCreateThreadEx", "RtlCreateUserThread"},
	"Descarga de contenido":    {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile", "WinHttpOpen", "WinHttpReadData", "HttpSendRequestA", "HttpSendRequestW"},
	"Captura de teclado":       {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState", "GetForegroundWindow"},
	"Anti-análisis":            {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount"},
	"Cifrado":                  {"CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt", "CryptGenKey"},
	"Escalada de privilegios":  {"AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW", "OpenProcessToken", "ImpersonateLoggedOnUser"},
	"Servicios y persistencia": {"CreateServiceA", "CreateServiceW", "StartServiceA", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"},
}

func entropia(hist *[256]int64, total int64) float64 {
	if total == 0 {
		return 0
	}
	var e float64
	for _, c := range hist {
		if c > 0 {
			p := float64(c) / float64(total)
			e -= p * math.Log2(p)
		}
	}
	return e
}

var (
	reURL       = regexp.MustCompile(`(?i)https?://[^\s"'<>\x00-\x1f]{4,200}`)
	reIP        = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reReg       = regexp.MustCompile(`(?i)(HKEY_[A-Z_]+\\[^\s"']{3,120}|SOFTWARE\\Microsoft\\Windows(?: NT)?\\CurrentVersion\\(?:Run|RunOnce|Winlogon|Image File Execution Options)[^\s"']*)`)
	reCmd       = regexp.MustCompile(`(?i)(powershell[^\r\n]{0,60}(-enc|-e\s|-w(indowstyle)?\s+hidden|iex|downloadstring|frombase64)|certutil[^\r\n]{0,40}-urlcache|bitsadmin[^\r\n]{0,30}/transfer|schtasks[^\r\n]{0,20}/create|reg(?:\.exe)?\s+add[^\r\n]{0,60}|cmd(?:\.exe)?\s+/c[^\r\n]{0,60}|mshta[^\r\n]{0,60}|wscript[^\r\n]{0,40}|vssadmin[^\r\n]{0,30}delete\s+shadows|wbadmin[^\r\n]{0,30}delete|bcdedit[^\r\n]{0,30}/set|netsh[^\r\n]{0,30}firewall[^\r\n]{0,30}(add|disable))`)
	reCmdFuerte = regexp.MustCompile(`(?i)(-enc\b|-encodedcommand|frombase64|downloadstring|\biex\b|urlcache|bitsadmin|mshta|-w(indowstyle)?\s+hidden)`)
	reRuta      = regexp.MustCompile(`(?i)[A-Z]:\\(?:[^\\/:*?"<>|\r\n\x00]{1,60}\\){1,6}[^\\/:*?"<>|\r\n\x00]{1,60}`)
)

func extraerCadenas(buf []byte, set map[string]bool) {
	// ASCII imprimible >= 6 y UTF-16LE imprimible >= 6
	start := -1
	for i := 0; i <= len(buf); i++ {
		if i < len(buf) && buf[i] >= 0x20 && buf[i] < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 6 && len(set) < 60000 {
			s := string(buf[start:i])
			if len(s) > 400 {
				s = s[:400]
			}
			set[s] = true
		}
		start = -1
	}
	var u []byte
	flush := func() {
		if len(u) >= 6 && len(set) < 60000 {
			s := string(u)
			if len(s) > 400 {
				s = s[:400]
			}
			set[s] = true
		}
		u = u[:0]
	}
	for i := 0; i+1 < len(buf); i += 2 {
		if buf[i] >= 0x20 && buf[i] < 0x7f && buf[i+1] == 0 {
			u = append(u, buf[i])
		} else {
			flush()
		}
	}
	flush()
}

func tipoArchivo(head []byte) string {
	switch {
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return "Ejecutable de Windows (PE)"
	case len(head) >= 4 && string(head[:4]) == "\x7fELF":
		return "Ejecutable ELF (Linux)"
	case len(head) >= 4 && string(head[:4]) == "PK\x03\x04":
		return "Archivo ZIP / Office moderno / JAR / APK"
	case len(head) >= 5 && string(head[:5]) == "%PDF-":
		return "Documento PDF"
	case len(head) >= 8 && string(head[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return "Documento OLE (Office antiguo, puede contener macros)"
	case len(head) >= 5 && string(head[:5]) == "{\\rtf":
		return "Documento RTF"
	case len(head) >= 4 && string(head[:4]) == "Rar!":
		return "Archivo RAR"
	case len(head) >= 4 && string(head[:4]) == "\x4c\x00\x00\x00":
		return "Acceso directo de Windows (.lnk)"
	case len(head) >= 2 && string(head[:2]) == "#!":
		return "Script con intérprete (shebang)"
	}
	t := 0
	for _, b := range head {
		if b == 9 || b == 10 || b == 13 || (b >= 0x20 && b < 0x7f) {
			t++
		}
	}
	if len(head) > 0 && t*100/len(head) > 95 {
		return "Texto / script"
	}
	return "Binario desconocido"
}

func analizarArchivo(j *Job, ruta, nombre string, subido bool) (*analisis, error) {
	st, err := os.Stat(ruta)
	if err != nil || st.IsDir() {
		return nil, errors.New("no es un archivo válido")
	}
	f, err := os.Open(ruta)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	a := &analisis{Nombre: nombre, Ruta: ruta, Tam: st.Size(), Subido: subido}
	if subido {
		a.Ruta = ""
	}
	h256, h1, hm := sha256.New(), sha1.New(), md5.New()
	w := io.MultiWriter(h256, h1, hm)
	var hist [256]int64
	var total int64
	set := map[string]bool{}
	buf := make([]byte, 4<<20)
	var head []byte
	const limCadenas = 64 << 20
	for {
		n, err := f.Read(buf)
		if n > 0 {
			c := buf[:n]
			_, _ = w.Write(c)
			for _, b := range c {
				hist[b]++
			}
			total += int64(n)
			if head == nil {
				head = append([]byte{}, c[:min(n, 512)]...)
			}
			if total <= limCadenas {
				extraerCadenas(c, set)
			} else {
				a.Truncado = true
			}
		}
		if err != nil {
			break
		}
		if j.ctx.Err() != nil {
			return nil, errors.New("cancelado")
		}
	}
	a.SHA256, a.SHA1, a.MD5 = hex.EncodeToString(h256.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(hm.Sum(nil))
	a.Entropia = math.Round(entropia(&hist, total)*100) / 100
	a.Tipo = tipoArchivo(head)

	add := func(tipo, texto string, peso int) {
		a.Hallazgos = append(a.Hallazgos, hallazgoArchivo{tipo, texto, peso})
		a.Score += peso
	}

	// ---- PE
	if strings.HasPrefix(a.Tipo, "Ejecutable de Windows") {
		if p, err := pe.Open(ruta); err == nil {
			defer p.Close()
			a.PE = analizarPE(p, st.Size(), add)
		} else {
			add("observado", "Empieza con «MZ» pero su cabecera PE no es válida ("+err.Error()+"): puede estar dañado o manipulado.", 2)
		}
	}
	if a.Entropia >= 7.4 && a.PE == nil && !strings.Contains(a.Tipo, "ZIP") && !strings.Contains(a.Tipo, "RAR") {
		add("inferido", fmt.Sprintf("Entropía muy alta (%.2f/8): el contenido parece cifrado o comprimido.", a.Entropia), 2)
	}

	// ---- cadenas
	lista := make([]string, 0, len(set))
	for s := range set {
		lista = append(lista, s)
	}
	sort.Strings(lista)
	a.Cadenas = clasificarCadenas(lista)
	if n := len(a.Cadenas.Comandos); n > 0 {
		fuertes := 0
		for _, c := range a.Cadenas.Comandos {
			if reCmdFuerte.MatchString(c) {
				fuertes++
			}
		}
		if fuertes > 0 {
			add("observado", fmt.Sprintf("Contiene %d fragmento(s) de comandos típicos de descarga u ofuscación (%d en total).", fuertes, n), 2)
		} else {
			add("observado", fmt.Sprintf("Contiene %d comando(s) de sistema (cmd, reg, netsh…). Es habitual en instaladores y herramientas legítimas; por sí solo no indica nada.", n), 0)
		}
	}
	if fuertes := ransomwareCmd(a.Cadenas.Comandos, a); fuertes {
		add("inferido", "Hace referencia a borrar copias de seguridad/instantáneas junto a otros indicadores: comportamiento típico de ransomware.", 3)
	}
	if len(a.Cadenas.Registro) > 0 {
		for _, r := range a.Cadenas.Registro {
			if strings.Contains(strings.ToLower(r), `currentversion\run`) || strings.Contains(strings.ToLower(r), "image file execution") {
				add("observado", "Menciona claves del registro usadas para persistencia (Run / IFEO).", 1)
				break
			}
		}
	}

	// ---- firma
	if !subido {
		if s := firmas([]string{ruta}); len(s) > 0 {
			for _, v := range s {
				v := v
				a.Firma = &v
			}
			switch a.Firma.Status {
			case "Valid":
				add("observado", "Firma digital válida de: "+nombreFirmante(a.Firma.Signer)+".", -2)
			case "NotSigned":
				if a.PE != nil {
					add("observado", "El ejecutable no tiene firma digital.", 1)
				}
			case "Error":
			default:
				add("observado", "La firma digital NO es válida ("+a.Firma.Status+"): el archivo pudo ser modificado.", 4)
			}
		}
	}

	if a.Score < 0 {
		a.Score = 0
	}
	switch {
	case a.Score >= 6:
		a.Veredicto = "alto"
	case a.Score >= 3:
		a.Veredicto = "medio"
	default:
		a.Veredicto = "bajo"
	}
	a.Yara = generarYara(a, lista)
	return a, nil
}

func flagsSeccion(c uint32) string {
	var s []string
	if c&0x20000000 != 0 {
		s = append(s, "X")
	}
	if c&0x40000000 != 0 {
		s = append(s, "R")
	}
	if c&0x80000000 != 0 {
		s = append(s, "W")
	}
	return strings.Join(s, "")
}

func analizarPE(p *pe.File, size int64, add func(string, string, int)) *peInfo {
	info := &peInfo{}
	switch p.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Maquina = "x64"
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Maquina = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		info.Maquina = "ARM64"
	default:
		info.Maquina = fmt.Sprintf("0x%x", p.Machine)
	}
	ts := time.Unix(int64(p.TimeDateStamp), 0).UTC()
	info.Compilado = ts.Format("2006-01-02 15:04")
	if p.TimeDateStamp == 0 {
		info.Compilado = "sin fecha"
	} else if ts.After(time.Now().Add(24 * time.Hour)) {
		add("observado", "La fecha de compilación está en el futuro ("+info.Compilado+"): puede estar falsificada.", 1)
	}
	var maxEnd int64
	for _, s := range p.Sections {
		sec := seccion{Nombre: strings.TrimRight(s.Name, "\x00"), Tam: s.Size, Flags: flagsSeccion(s.Characteristics)}
		if data, err := s.Data(); err == nil && len(data) > 0 {
			var h [256]int64
			for _, b := range data {
				h[b]++
			}
			sec.Entropia = math.Round(entropia(&h, int64(len(data)))*100) / 100
		}
		info.Secciones = append(info.Secciones, sec)
		if e := int64(s.Offset) + int64(s.Size); e > maxEnd {
			maxEnd = e
		}
		if sec.Entropia >= 7.2 && s.Characteristics&0x20000000 != 0 {
			add("inferido", fmt.Sprintf("La sección de código «%s» tiene entropía %.2f: es típico de ejecutables empaquetados u ofuscados.", sec.Nombre, sec.Entropia), 2)
		}
		if s.Characteristics&0x20000000 != 0 && s.Characteristics&0x80000000 != 0 {
			add("observado", fmt.Sprintf("La sección «%s» es ejecutable y escribible a la vez (inusual en programas normales).", sec.Nombre), 2)
		}
	}
	if maxEnd > 0 && size > maxEnd {
		info.Overlay = size - maxEnd
	}
	var dllChars uint16
	switch oh := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.Subsis = subsistema(oh.Subsystem)
		dllChars = oh.DllCharacteristics
		info.Firmada = len(oh.DataDirectory) > 4 && oh.DataDirectory[4].Size > 0
	case *pe.OptionalHeader64:
		info.Subsis = subsistema(oh.Subsystem)
		dllChars = oh.DllCharacteristics
		info.Firmada = len(oh.DataDirectory) > 4 && oh.DataDirectory[4].Size > 0
	}
	info.ASLR, info.DEP = dllChars&0x40 != 0, dllChars&0x100 != 0

	syms, _ := p.ImportedSymbols()
	info.Importes = len(syms)
	nom := map[string]bool{}
	for _, s := range syms {
		if i := strings.Index(s, ":"); i > 0 {
			s = s[:i]
		}
		nom[s] = true
	}
	var cats []string
	for c := range apisSospechosas {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		var hit []string
		for _, fn := range apisSospechosas[c] {
			if nom[fn] {
				hit = append(hit, fn)
			}
		}
		if len(hit) > 0 {
			info.APIs = append(info.APIs, apiHit{c, hit})
		}
	}
	for _, h := range info.APIs {
		if h.Categoria == "Inyección en procesos" && len(h.Funciones) >= 3 {
			add("inferido", "Importa varias funciones de inyección en procesos ("+strings.Join(h.Funciones, ", ")+").", 3)
		}
		if h.Categoria == "Captura de teclado" && len(h.Funciones) >= 2 {
			add("inferido", "Importa funciones que permiten registrar pulsaciones de teclado.", 1)
		}
	}
	if info.Importes > 0 && info.Importes < 6 {
		add("inferido", fmt.Sprintf("Importa muy pocas funciones (%d): los empaquetadores resuelven las demás en tiempo de ejecución.", info.Importes), 1)
	}
	if info.Overlay > 0 && info.Overlay > size/2 && size > 100000 {
		add("observado", fmt.Sprintf("Más de la mitad del archivo (%d KB) son datos añadidos al final, fuera de las secciones.", info.Overlay/1024), 1)
	}
	return info
}

func subsistema(v uint16) string {
	switch v {
	case 2:
		return "Interfaz gráfica"
	case 3:
		return "Consola"
	case 1:
		return "Nativo"
	}
	return fmt.Sprint(v)
}

func clasificarCadenas(lista []string) cadenasInfo {
	ci := cadenasInfo{Total: len(lista), URLs: []string{}, IPs: []string{}, Registro: []string{}, Comandos: []string{}, Rutas: []string{}, Muestra: []string{}}
	uniq := func(dst *[]string, v string, max int) {
		for _, x := range *dst {
			if x == v {
				return
			}
		}
		if len(*dst) < max {
			*dst = append(*dst, v)
		}
	}
	for _, s := range lista {
		for _, m := range reURL.FindAllString(s, 3) {
			uniq(&ci.URLs, m, 40)
		}
		for _, m := range reIP.FindAllString(s, 3) {
			if ip := net.ParseIP(m); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !strings.HasPrefix(m, "0.") && !esVersion(m) {
				uniq(&ci.IPs, m, 30)
			}
		}
		for _, m := range reReg.FindAllString(s, 2) {
			uniq(&ci.Registro, m, 30)
		}
		for _, m := range reCmd.FindAllString(s, 2) {
			uniq(&ci.Comandos, strings.TrimSpace(m), 30)
		}
		for _, m := range reRuta.FindAllString(s, 1) {
			uniq(&ci.Rutas, m, 30)
		}
	}
	// muestra: las cadenas mas largas (suelen ser las mas informativas)
	sorted := append([]string{}, lista...)
	sort.Slice(sorted, func(a, b int) bool { return len(sorted[a]) > len(sorted[b]) })
	for i := 0; i < len(sorted) && i < 40; i++ {
		ci.Muestra = append(ci.Muestra, sorted[i])
	}
	return ci
}

// esVersion descarta numeros como 6.1.7601.17514 que parecen IP pero son versiones.
func esVersion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if n, _ := strconv.Atoi(p); n > 255 {
			return true
		}
	}
	return false
}

func generarYara(a *analisis, cadenas []string) string {
	id := regexp.MustCompile(`[^A-Za-z0-9_]`).ReplaceAllString(strings.TrimSuffix(a.Nombre, filepath.Ext(a.Nombre)), "_")
	if id == "" || (id[0] >= '0' && id[0] <= '9') {
		id = "f_" + id
	}
	// candidatas: cadenas largas, no triviales, preferentemente de URL/comando/registro/ruta
	cand := []string{}
	pref := append(append(append([]string{}, a.Cadenas.Comandos...), a.Cadenas.URLs...), a.Cadenas.Registro...)
	for _, s := range pref {
		if len(s) >= 8 && len(s) <= 120 {
			cand = append(cand, s)
		}
	}
	if len(cand) < 6 {
		for _, s := range a.Cadenas.Muestra {
			if len(s) >= 12 && len(s) <= 100 && !strings.ContainsAny(s, "\x00") {
				cand = append(cand, s)
			}
		}
	}
	seen := map[string]bool{}
	var sel []string
	for _, s := range cand {
		if !seen[s] && len(sel) < 8 {
			seen[s] = true
			sel = append(sel, s)
		}
	}
	esc := func(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) }
	var b strings.Builder
	fmt.Fprintf(&b, "// BORRADOR generado automáticamente. SIN VALIDAR: pruébalo contra muestras limpias antes de usarlo.\nrule %s\n{\n  meta:\n", id)
	fmt.Fprintf(&b, "    description = \"Regla de ejemplo para %s\"\n    sha256 = \"%s\"\n    generado = \"%s\"\n  strings:\n", esc(a.Nombre), a.SHA256, time.Now().Format("2006-01-02"))
	for i, s := range sel {
		fmt.Fprintf(&b, "    $s%d = \"%s\" ascii wide\n", i+1, esc(s))
	}
	cond := "filesize < " + strconv.FormatInt(a.Tam*2+1024, 10)
	if a.PE != nil {
		cond = "uint16(0) == 0x5A4D and " + cond
	}
	switch {
	case len(sel) >= 4:
		cond += fmt.Sprintf(" and %d of ($s*)", len(sel)/2)
	case len(sel) > 0:
		cond += " and any of ($s*)"
	default:
		cond += " and hash.sha256(0, filesize) == \"" + a.SHA256 + "\"" // requiere import "hash"
		return "import \"hash\"\n" + b.String() + "  condition:\n    " + cond + "\n}\n"
	}
	return b.String() + "  condition:\n    " + cond + "\n}\n"
}

// ================================================================== 4) EVENTOS DE SEGURIDAD

type xmlEvent struct {
	System struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			T string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

type evento struct {
	Hora   string `json:"hora"`
	ID     int    `json:"id"`
	Canal  string `json:"canal"`
	Texto  string `json:"texto"`
	Quien  string `json:"quien"`
	Origen string `json:"origen"`
	data   map[string]string
}

var reEventBlock = regexp.MustCompile(`(?s)<Event[ >].*?</Event>`)

func parseEventos(xmlText, canal string) []evento {
	var out []evento
	for _, blk := range reEventBlock.FindAllString(xmlText, -1) {
		var x xmlEvent
		if xml.Unmarshal([]byte(blk), &x) != nil {
			continue
		}
		e := evento{ID: x.System.EventID, Canal: canal, Hora: x.System.TimeCreated.T, data: map[string]string{}}
		if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.T); err == nil {
			e.Hora = t.Local().Format("2006-01-02 15:04:05")
		}
		for _, d := range x.EventData.Data {
			e.data[d.Name] = strings.TrimSpace(d.Value)
		}
		out = append(out, e)
	}
	return out
}

func consultarEventos(canal string, ids []int, horas, max int) ([]evento, error) {
	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	q := fmt.Sprintf("*[System[(%s) and TimeCreated[timediff(@SystemTime) <= %d]]]", strings.Join(parts, " or "), int64(horas)*3600*1000)
	out, err := nativeOutput(90*time.Second, "wevtutil", "qe", canal, "/q:"+q, "/f:xml", "/c:"+strconv.Itoa(max), "/rd:true")
	if err != nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "denied") || strings.Contains(low, "denegado") || strings.Contains(low, "5") && strings.Contains(low, "access") {
			return nil, errors.New("acceso denegado al registro «" + canal + "» (se necesitan permisos de administrador)")
		}
		if strings.TrimSpace(out) == "" {
			return nil, err
		}
		return nil, errors.New(firstLine(strings.TrimSpace(out)))
	}
	return parseEventos(out, canal), nil
}

type alerta struct {
	Nivel  string `json:"nivel"`
	Titulo string `json:"titulo"`
	Texto  string `json:"texto"`
}

type eventosResult struct {
	Horas   int            `json:"horas"`
	Conteos map[string]int `json:"conteos"`
	Alertas []alerta       `json:"alertas"`
	Eventos []evento       `json:"eventos"`
	Notas   []string       `json:"notas"`
}

var descEvento = map[int]string{4625: "Inicio de sesión fallido", 4624: "Inicio de sesión correcto", 4720: "Cuenta de usuario creada", 4722: "Cuenta de usuario habilitada",
	4724: "Contraseña restablecida", 4732: "Usuario añadido a un grupo local", 4728: "Usuario añadido a un grupo global", 1102: "Registro de auditoría BORRADO",
	7045: "Servicio instalado", 4698: "Tarea programada creada", 1116: "Defender: amenaza detectada", 1117: "Defender: acción contra amenaza", 4740: "Cuenta bloqueada"}

func ipValida(ip string) bool {
	return ip != "" && ip != "-" && ip != "::1" && ip != "127.0.0.1" && !strings.HasPrefix(ip, "fe80")
}

func analizarEventos(evs []evento) ([]alerta, map[string]int) {
	var al []alerta
	count := map[string]int{}
	failIP, failUser := map[string]int{}, map[string]int{}
	usersPorIP := map[string]map[string]bool{}
	for _, e := range evs {
		count[strconv.Itoa(e.ID)]++
		d := e.data
		switch e.ID {
		case 4625:
			ip, u := d["IpAddress"], d["TargetUserName"]
			e.Quien, e.Origen = u, ip
			if ipValida(ip) {
				failIP[ip]++
				if usersPorIP[ip] == nil {
					usersPorIP[ip] = map[string]bool{}
				}
				usersPorIP[ip][u] = true
			}
			failUser[u]++
		case 1102:
			al = append(al, alerta{"alto", "Se borró el registro de auditoría", "El " + e.Hora + " alguien limpió el registro de seguridad (" + d["SubjectUserName"] + "). Es una técnica habitual para ocultar rastros."})
		case 4732, 4728:
			if d["TargetSid"] == "S-1-5-32-544" || strings.EqualFold(d["TargetUserName"], "Administrators") || strings.EqualFold(d["TargetUserName"], "Administradores") {
				al = append(al, alerta{"alto", "Se añadió un usuario al grupo Administradores", fmt.Sprintf("El %s: «%s» fue añadido por «%s». Comprueba que lo hiciste tú.", e.Hora, d["MemberName"], d["SubjectUserName"])})
			}
		case 4720:
			al = append(al, alerta{"medio", "Se creó una cuenta de usuario", fmt.Sprintf("El %s se creó «%s» (por «%s»).", e.Hora, d["TargetUserName"], d["SubjectUserName"])})
		case 7045:
			al = append(al, alerta{"medio", "Se instaló un servicio", fmt.Sprintf("El %s: «%s» → %s", e.Hora, d["ServiceName"], d["ImagePath"])})
		case 4698:
			al = append(al, alerta{"medio", "Se creó una tarea programada", fmt.Sprintf("El %s: «%s» (por «%s»).", e.Hora, d["TaskName"], d["SubjectUserName"])})
		case 4740:
			al = append(al, alerta{"medio", "Cuenta bloqueada por intentos fallidos", fmt.Sprintf("El %s se bloqueó «%s».", e.Hora, d["TargetUserName"])})
		case 1116:
			al = append(al, alerta{"alto", "Microsoft Defender detectó una amenaza", fmt.Sprintf("El %s: %s en %s.", e.Hora, d["Threat Name"], d["Path"])})
		}
	}
	for ip, n := range failIP {
		if n >= 10 {
			al = append(al, alerta{"alto", "Posible ataque de fuerza bruta", fmt.Sprintf("%d inicios de sesión fallidos desde %s en este periodo.", n, ip)})
		}
		if len(usersPorIP[ip]) >= 5 && n >= 5 {
			al = append(al, alerta{"alto", "Posible «password spraying»", fmt.Sprintf("%s probó %d usuarios distintos (%d intentos fallidos).", ip, len(usersPorIP[ip]), n)})
		}
	}
	for u, n := range failUser {
		if n >= 10 && u != "" {
			al = append(al, alerta{"medio", "Muchos fallos para una cuenta", fmt.Sprintf("%d intentos fallidos con el usuario «%s».", n, u)})
		}
	}
	rank := map[string]int{"alto": 0, "medio": 1, "bajo": 2}
	sort.SliceStable(al, func(a, b int) bool { return rank[al[a].Nivel] < rank[al[b].Nivel] })
	if len(al) > 60 {
		al = al[:60]
	}
	return al, count
}

func leerEventosSeguridad(j *Job, horas int) eventosResult {
	if horas < 1 || horas > 24*90 {
		horas = 168
	}
	res := eventosResult{Horas: horas, Alertas: []alerta{}, Eventos: []evento{}, Notas: []string{}}
	var todos []evento
	consultas := []struct {
		canal string
		ids   []int
		max   int
	}{
		{"Security", []int{4625, 4624, 4720, 4722, 4724, 4732, 4728, 4740, 4698, 1102}, 3000},
		{"System", []int{7045}, 200},
		{"Microsoft-Windows-Windows Defender/Operational", []int{1116, 1117}, 100},
	}
	for _, c := range consultas {
		j.log("Leyendo registro: " + c.canal + " ...")
		ev, err := consultarEventos(c.canal, c.ids, horas, c.max)
		if err != nil {
			res.Notas = append(res.Notas, c.canal+": "+err.Error())
			continue
		}
		todos = append(todos, ev...)
	}
	res.Alertas, res.Conteos = analizarEventos(todos)
	// filas legibles
	for i := range todos {
		e := &todos[i]
		d := e.data
		e.Texto = descEvento[e.ID]
		switch e.ID {
		case 4625:
			e.Quien, e.Origen = d["TargetUserName"], d["IpAddress"]
		case 4624:
			e.Quien, e.Origen = d["TargetUserName"], d["IpAddress"]
			if lt := d["LogonType"]; lt != "" {
				e.Texto += " (tipo " + lt + ")"
			}
		case 4720, 4722, 4724, 4740:
			e.Quien = d["TargetUserName"]
		case 4732, 4728:
			e.Quien = d["MemberName"]
		case 7045:
			e.Quien = d["ServiceName"]
		case 4698:
			e.Quien = d["TaskName"]
		case 1116, 1117:
			e.Quien = d["Threat Name"]
		case 1102:
			e.Quien = d["SubjectUserName"]
		}
	}
	// los inicios correctos (muy numerosos) solo se resumen; el resto se lista
	for _, e := range todos {
		if e.ID == 4624 {
			continue
		}
		res.Eventos = append(res.Eventos, e)
		if len(res.Eventos) >= 400 {
			break
		}
	}
	if res.Conteos["4625"] == 0 && res.Conteos["4624"] == 0 {
		res.Notas = append(res.Notas, "No hay inicios de sesión registrados: la auditoría de inicios de sesión puede estar desactivada (puedes activarla abajo).")
	}
	j.log(fmt.Sprintf("[OK] %d eventos analizados; %d alerta(s).", len(todos), len(res.Alertas)))
	return res
}

const guidAuditLogon = "{0CCE9215-69AE-11D9-BED3-505054503030}"

func activarAuditoriaLogon() error {
	out, err := nativeOutput(30*time.Second, "auditpol", "/set", "/subcategory:"+guidAuditLogon, "/success:enable", "/failure:enable")
	if err != nil {
		return fmt.Errorf("auditpol: %s", strings.TrimSpace(out))
	}
	return nil
}

// ransomwareCmd: borrar instantaneas solo cuenta si ademas hay otros indicadores (descarga/ofuscacion
// o cifrado), porque muchas herramientas de copia de seguridad mencionan vssadmin legitimamente.
func ransomwareCmd(cmds []string, a *analisis) bool {
	vss := false
	for _, c := range cmds {
		l := strings.ToLower(c)
		if strings.Contains(l, "delete") && (strings.Contains(l, "shadow") || strings.Contains(l, "wbadmin")) {
			vss = true
		}
	}
	if !vss {
		return false
	}
	for _, c := range cmds {
		if reCmdFuerte.MatchString(c) {
			return true
		}
	}
	if a.PE != nil {
		for _, h := range a.PE.APIs {
			if h.Categoria == "Cifrado" {
				return true
			}
		}
	}
	return false
}
