//go:build windows

package main

// Capa nativa de Windows: todo lo esencial se lee/escribe con APIs reales del sistema
// (registro, procesos, servicios, discos, memoria). PowerShell solo se usa en las pocas
// funciones que no tienen API sencilla (apps de la Tienda, usuarios locales, salud SMART).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")

	pGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	pGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	pGetTickCount64       = kernel32.NewProc("GetTickCount64")
	pProcMemInfo          = kernel32.NewProc("K32GetProcessMemoryInfo")
	pSHEmptyRecycleBin    = shell32.NewProc("SHEmptyRecycleBinW")
	pSHFileOperation      = shell32.NewProc("SHFileOperationW")
	pMessageBox           = user32.NewProc("MessageBoxW")
)

const (
	createNoWindow = 0x08000000
	cpOEM          = 1
)

func hideProc(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// ------------------------------------------------------------------ admin / ventana

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

func elevate() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	args := strings.Join(os.Args[1:], " ")
	err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(args), nil, windows.SW_NORMAL)
	return err == nil
}

func showMessage(title, msg string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(msg)
	pMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

func openWindow(url string) {
	local := os.Getenv("LOCALAPPDATA")
	pf, pf86 := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")
	cands := []string{
		filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
	}
	profile := filepath.Join(local, "OptimizadorPC", "perfil")
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			cmd := exec.Command(c, "--app="+url, "--window-size=1240,820", "--no-first-run",
				"--disable-features=Translate", "--user-data-dir="+profile)
			if cmd.Start() == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// ------------------------------------------------------------------ memoria / CPU / discos

type memStatus struct {
	Length, MemoryLoad                                                             uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual uint64
	AvailExtendedVirtual                                                           uint64
}

func memInfo() (total, avail uint64) {
	var m memStatus
	m.Length = uint32(unsafe.Sizeof(m))
	if r, _, _ := pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r != 0 {
		return m.TotalPhys, m.AvailPhys
	}
	return 0, 0
}

func uptimeSeconds() uint64 {
	r, _, _ := pGetTickCount64.Call()
	return uint64(r) / 1000
}

func ft(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

var (
	cpuMu        sync.Mutex
	cpuPrevIdle  uint64
	cpuPrevTotal uint64
	cpuLastPct   float64
	cpuLastAt    time.Time
)

// cpuPercent: uso global de CPU entre dos llamadas consecutivas.
func cpuPercent() float64 {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	var idle, kern, usr windows.Filetime
	if r, _, _ := pGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&usr))); r == 0 {
		return 0
	}
	i, k, u := ft(idle), ft(kern), ft(usr)
	total := k + u // el tiempo de kernel ya incluye el idle
	if cpuPrevTotal != 0 && time.Since(cpuLastAt) > 300*time.Millisecond && total > cpuPrevTotal {
		dt, di := total-cpuPrevTotal, i-cpuPrevIdle
		p := (1 - float64(di)/float64(dt)) * 100
		if p < 0 {
			p = 0
		}
		cpuLastPct = p
	}
	if time.Since(cpuLastAt) > 300*time.Millisecond {
		cpuPrevIdle, cpuPrevTotal, cpuLastAt = i, total, time.Now()
	}
	return cpuLastPct
}

type diskInfo struct {
	Letter string `json:"letra"`
	Label  string `json:"etiqueta"`
	FS     string `json:"fs"`
	Free   uint64 `json:"libre"`
	Total  uint64 `json:"total"`
	Kind   string `json:"tipo"`
}

func fixedDisks() []diskInfo {
	var out []diskInfo
	mask, _ := windows.GetLogicalDrives()
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := windows.UTF16PtrFromString(root)
		dt := windows.GetDriveType(rp)
		if dt != windows.DRIVE_FIXED {
			continue
		}
		var freeAvail, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(rp, &freeAvail, &total, &totalFree); err != nil {
			continue
		}
		label := make([]uint16, 261)
		fsn := make([]uint16, 261)
		var serial, maxc, flags uint32
		_ = windows.GetVolumeInformation(rp, &label[0], 261, &serial, &maxc, &flags, &fsn[0], 261)
		out = append(out, diskInfo{Letter: root[:2], Label: windows.UTF16ToString(label), FS: windows.UTF16ToString(fsn),
			Free: freeAvail, Total: total, Kind: "fijo"})
	}
	return out
}

// ------------------------------------------------------------------ registro

func regStr(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return s
}

func regDword(root registry.Key, path, name string) (uint32, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func regSubkeys(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	n, _ := k.ReadSubKeyNames(-1)
	return n
}

// ------------------------------------------------------------------ informacion del sistema

func systemInfo() map[string]interface{} {
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	hostname, _ := os.Hostname()
	prod := regStr(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regStr(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	disp := regStr(registry.LOCAL_MACHINE, cv, "DisplayVersion")
	if disp == "" {
		disp = regStr(registry.LOCAL_MACHINE, cv, "ReleaseId")
	}
	var b int
	fmt.Sscanf(build, "%d", &b)
	if b >= 22000 {
		prod = strings.Replace(prod, "Windows 10", "Windows 11", 1)
	}
	cpu := strings.Join(strings.Fields(regStr(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")), " ")
	var gpus []string
	for _, sk := range regSubkeys(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`) {
		if len(sk) != 4 {
			continue
		}
		d := regStr(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\`+sk, "DriverDesc")
		if d != "" {
			gpus = append(gpus, d)
		}
	}
	const bios = `HARDWARE\DESCRIPTION\System\BIOS`
	total, avail := memInfo()
	return map[string]interface{}{
		"equipo":     hostname,
		"windows":    strings.TrimSpace(prod + " " + disp),
		"build":      build,
		"cpu":        cpu,
		"nucleos":    fmt.Sprint(runtimeCPUs()),
		"gpu":        gpus,
		"fabricante": regStr(registry.LOCAL_MACHINE, bios, "SystemManufacturer"),
		"modelo":     regStr(registry.LOCAL_MACHINE, bios, "SystemProductName"),
		"placa":      regStr(registry.LOCAL_MACHINE, bios, "BaseBoardProduct"),
		"bios":       regStr(registry.LOCAL_MACHINE, bios, "BIOSVersion"),
		"ramTotal":   total,
		"ramLibre":   avail,
		"horas":      uptimeSeconds() / 3600,
		"discos":     fixedDisks(),
		"usuario":    os.Getenv("USERNAME"),
	}
}

// ------------------------------------------------------------------ procesos

type procInfo struct {
	PID     uint32  `json:"pid"`
	Name    string  `json:"nombre"`
	Mem     uint64  `json:"mem"`
	CPU     float64 `json:"cpu"`
	Threads uint32  `json:"hilos"`
}

type procMemCounters struct {
	CB, PageFaultCount                                                                   uint32
	PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage     uintptr
	QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage uintptr
}

func snapshotProcs() map[uint32]*procInfo {
	out := map[uint32]*procInfo{}
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(h)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if windows.Process32First(h, &e) != nil {
		return out
	}
	for {
		out[e.ProcessID] = &procInfo{PID: e.ProcessID, Name: windows.UTF16ToString(e.ExeFile[:]), Threads: e.Threads}
		if windows.Process32Next(h, &e) != nil {
			break
		}
	}
	return out
}

func procTimes(pid uint32) (uint64, uint64, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, 0, false
	}
	defer windows.CloseHandle(h)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) != nil {
		return 0, 0, false
	}
	return ft(k) + ft(u), 0, true
}

func procMem(pid uint32) uint64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var c procMemCounters
	c.CB = uint32(unsafe.Sizeof(c))
	if r, _, _ := pProcMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.CB)); r == 0 {
		return 0
	}
	return uint64(c.WorkingSetSize)
}

// listProcesses mide el CPU real de cada proceso con dos muestras separadas.
func listProcesses() []*procInfo {
	a := snapshotProcs()
	t1 := map[uint32]uint64{}
	for pid := range a {
		if t, _, ok := procTimes(pid); ok {
			t1[pid] = t
		}
	}
	start := time.Now()
	time.Sleep(700 * time.Millisecond)
	b := snapshotProcs()
	wall := float64(time.Since(start).Nanoseconds()) / 100 // en unidades de 100 ns
	ncpu := float64(runtimeCPUs())
	var list []*procInfo
	for pid, p := range b {
		if t2, _, ok := procTimes(pid); ok {
			if t, had := t1[pid]; had && t2 >= t {
				p.CPU = float64(t2-t) / (wall * ncpu) * 100
			}
		}
		p.Mem = procMem(pid)
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Mem > list[j].Mem })
	return list
}

var protegidos = map[string]bool{
	"system": true, "system idle process": true, "registry": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "winlogon.exe": true, "services.exe": true, "lsass.exe": true, "lsm.exe": true,
	"memory compression": true, "fontdrvhost.exe": true, "dwm.exe": true, "svchost.exe": true,
	"secure system": true, "sihost.exe": true, "ctfmon.exe": true,
}

func killProcess(pid uint32, name string) error {
	if pid <= 4 || pid == uint32(os.Getpid()) {
		return errors.New("proceso protegido")
	}
	cur := snapshotProcs()[pid]
	if cur == nil || !strings.EqualFold(cur.Name, name) {
		return errors.New("el proceso ya no existe o cambió")
	}
	if protegidos[strings.ToLower(cur.Name)] {
		return errors.New("'" + cur.Name + "' es un proceso crítico de Windows; cerrarlo podría bloquear el equipo")
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el proceso: %v", err)
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// ------------------------------------------------------------------ servicios

type serviceInfo struct {
	Name    string `json:"nombre"`
	Display string `json:"visible"`
	State   string `json:"estado"`
	Start   string `json:"inicio"`
	Locked  bool   `json:"critico"`
}

var serviciosCriticos = map[string]bool{
	"rpcss": true, "rpceptmapper": true, "dcomlaunch": true, "lsm": true, "samss": true, "eventlog": true,
	"winmgmt": true, "plugplay": true, "power": true, "profsvc": true, "brokerinfrastructure": true,
	"systemeventsbroker": true, "gpsvc": true, "cryptsvc": true, "bfe": true, "mpssvc": true, "nsi": true,
	"dhcp": true, "dnscache": true, "lanmanworkstation": true, "staterepository": true, "usermanager": true,
	"schedule": true, "trustedinstaller": true, "wudfsvc": true, "windefend": true, "coremessagingregistrar": true,
	"termservice": false,
}

type svcCfg struct {
	Type, Start uint32
	Display     string
}

// querySvcConfig usa QueryServiceConfig directamente (sin consultas opcionales de descripcion).
func querySvcConfig(s *mgr.Service) (svcCfg, error) {
	var needed uint32
	err := windows.QueryServiceConfig(s.Handle, nil, 0, &needed)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || needed == 0 {
		if err == nil {
			err = errors.New("sin datos")
		}
		return svcCfg{}, err
	}
	buf := make([]byte, needed)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(s.Handle, cfg, needed, &needed); err != nil {
		return svcCfg{}, err
	}
	return svcCfg{Type: cfg.ServiceType, Start: cfg.StartType, Display: windows.UTF16PtrToString(cfg.DisplayName)}, nil
}

func setSvcStart(s *mgr.Service, start uint32) error {
	const noChange = 0xffffffff
	return windows.ChangeServiceConfig(s.Handle, noChange, start, noChange, nil, nil, nil, nil, nil, nil, nil)
}

func stateName(s svc.State) string {
	switch s {
	case svc.Running:
		return "En ejecución"
	case svc.Stopped:
		return "Detenido"
	case svc.StartPending:
		return "Iniciando"
	case svc.StopPending:
		return "Deteniendo"
	case svc.Paused:
		return "En pausa"
	}
	return "—"
}

func startName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "Automático"
	case mgr.StartManual:
		return "Manual"
	case mgr.StartDisabled:
		return "Deshabilitado"
	}
	return "Otro"
}

func listServices() ([]serviceInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := []serviceInfo{}
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		cfg, e1 := querySvcConfig(s)
		st, e2 := s.Query()
		s.Close()
		if e1 != nil || e2 != nil || cfg.Type&(windows.SERVICE_WIN32_OWN_PROCESS|windows.SERVICE_WIN32_SHARE_PROCESS) == 0 {
			continue
		}
		out = append(out, serviceInfo{Name: n, Display: cfg.Display, State: stateName(st.State),
			Start: startName(cfg.Start), Locked: serviciosCriticos[strings.ToLower(n)]})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Display) < strings.ToLower(out[j].Display) })
	return out, nil
}

func waitState(s *mgr.Service, want svc.State, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		st, err := s.Query()
		if err == nil && st.State == want {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func serviceAction(name, action string) error {
	low := strings.ToLower(name)
	if serviciosCriticos[low] && action != "start" {
		return errors.New("servicio crítico de Windows: no se permite detenerlo ni cambiarlo")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	switch action {
	case "start":
		if err := s.Start(); err != nil {
			return err
		}
		if !waitState(s, svc.Running, 15*time.Second) {
			return errors.New("el servicio no llegó a iniciarse a tiempo")
		}
	case "stop":
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		if !waitState(s, svc.Stopped, 20*time.Second) {
			return errors.New("el servicio no se detuvo a tiempo")
		}
	case "auto", "manual", "disabled":
		return setSvcStart(s, map[string]uint32{"auto": mgr.StartAutomatic, "manual": mgr.StartManual, "disabled": mgr.StartDisabled}[action])
	default:
		return errors.New("accion desconocida")
	}
	return nil
}

// withServiceStopped detiene un servicio mientras corre fn y lo reinicia si estaba en marcha.
func withServiceStopped(names []string, fn func()) {
	m, err := mgr.Connect()
	if err != nil {
		fn()
		return
	}
	defer m.Disconnect()
	var restart []string
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			if _, err := s.Control(svc.Stop); err == nil && waitState(s, svc.Stopped, 20*time.Second) {
				restart = append(restart, n)
			}
		}
		s.Close()
	}
	fn()
	for _, n := range restart {
		if s, err := m.OpenService(n); err == nil {
			_ = s.Start()
			s.Close()
		}
	}
}

// ------------------------------------------------------------------ papelera / explorador

func emptyRecycleBin() error {
	r, _, _ := pSHEmptyRecycleBin.Call(0, 0, 0x7) // sin confirmacion, sin progreso, sin sonido
	if r != 0 && uint32(r) != 0x8000FFFF {        // E_UNEXPECTED: la papelera ya estaba vacia
		return fmt.Errorf("HRESULT 0x%x", uint32(r))
	}
	return nil
}

type shFileOp struct {
	Hwnd    uintptr
	Func    uint32
	From    *uint16
	To      *uint16
	Flags   uint16
	Aborted int32
	Maps    uintptr
	Title   *uint16
}

// moveToRecycleBin envia archivos a la papelera (se pueden restaurar).
func moveToRecycleBin(paths []string) error {
	var buf []uint16
	for _, p := range paths {
		buf = append(buf, utf16.Encode([]rune(p))...)
		buf = append(buf, 0)
	}
	buf = append(buf, 0)
	op := shFileOp{Func: 3 /*FO_DELETE*/, From: &buf[0], Flags: 0x40 | 0x10 | 0x4 | 0x400}
	r, _, _ := pSHFileOperation.Call(uintptr(unsafe.Pointer(&op)))
	if r != 0 {
		return fmt.Errorf("código %d", r)
	}
	if op.Aborted != 0 {
		return errors.New("operación cancelada")
	}
	return nil
}

func revealInExplorer(path string) error {
	c := exec.Command("explorer.exe")
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `explorer.exe /select,"` + path + `"`}
	return c.Start()
}

func restartExplorer() error {
	_ = exec.Command("taskkill", "/F", "/IM", "explorer.exe").Run()
	time.Sleep(600 * time.Millisecond)
	return exec.Command("explorer.exe").Start()
}

// ------------------------------------------------------------------ ejecucion de comandos

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		return s[:i]
	}
	return s
}

func decodeOEM(b []byte) string {
	b = bytes.ReplaceAll(b, []byte{0}, nil) // sfc.exe emite UTF-16: se descartan los NUL
	if len(b) == 0 {
		return ""
	}
	n, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), &w[0], n); err != nil {
		return string(b)
	}
	return string(utf16.Decode(w))
}

func splitCRLF(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

var progressBar = regexp.MustCompile(`^\s*\[[= ]*[\d.,]*%?[= ]*\]\s*[\d.,]*%?\s*$`)

func stream(j *Job, cmd *exec.Cmd, oem bool) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	sc.Split(splitCRLF)
	for sc.Scan() {
		line := string(sc.Bytes())
		if oem {
			line = decodeOEM(sc.Bytes())
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || progressBar.MatchString(line) {
			continue
		}
		j.log("  " + line)
	}
	return cmd.Wait()
}

// runNative ejecuta una herramienta de Windows mostrando su salida en vivo. Se puede cancelar.
func runNative(j *Job, exe string, args ...string) error {
	cmd := exec.CommandContext(j.ctx, exe, args...)
	hideProc(cmd)
	return stream(j, cmd, true)
}

// nativeOutput ejecuta y devuelve la salida completa (OEM -> UTF-8).
func nativeOutput(timeout time.Duration, exe string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	hideProc(cmd)
	out, err := cmd.CombinedOutput()
	return decodeOEM(out), err
}

func psCommand(ctx context.Context, script string, envv map[string]string) *exec.Cmd {
	pre := "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
	u16 := utf16.Encode([]rune(pre + script))
	buf := make([]byte, 0, len(u16)*2)
	for _, v := range u16 {
		buf = append(buf, byte(v), byte(v>>8))
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(buf))
	hideProc(cmd)
	cmd.Env = os.Environ()
	for k, v := range envv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}

// psOutput: PowerShell solo para lo que no tiene API sencilla.
func psOutput(script string, envv map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := psCommand(ctx, script, envv)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(firstLine(msg))
	}
	return strings.TrimSpace(strings.TrimPrefix(out.String(), "\ufeff")), nil
}

func runPS(j *Job, script string, envv map[string]string) error {
	return stream(j, psCommand(j.ctx, script, envv), false)
}

// ------------------------------------------------------------------ desinstalacion

var reMsi = regexp.MustCompile(`(?i)^\s*"?(?:[^"]*\\)?msiexec(?:\.exe)?"?\s*`)

func lanzarDesinstalador(cmdline string) error {
	var c *exec.Cmd
	if reMsi.MatchString(cmdline) {
		rest := strings.TrimSpace(reMsi.ReplaceAllString(cmdline, ""))
		rest = strings.NewReplacer("/I", "/X", "/i", "/X").Replace(rest)
		c = exec.Command("msiexec.exe")
		c.SysProcAttr = &syscall.SysProcAttr{CmdLine: "msiexec.exe " + rest + " /passive /norestart"}
	} else {
		c = exec.Command("cmd.exe")
		c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /c "` + cmdline + `"`}
	}
	if err := c.Start(); err != nil {
		return err
	}
	go c.Wait()
	return nil
}
