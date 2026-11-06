//go:build windows

// Instalador / desinstalador de Optimizador PC (un solo Setup.exe).
package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed payload/OptimizadorPC.exe
var payload []byte

const (
	appName    = "Optimizador PC"
	appVersion = "1.0.0"
	publisher  = "Optimizador PC"
	exeName    = "OptimizadorPC.exe"
	uninstName = "Desinstalar.exe"
	regKey     = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OptimizadorPC`
)

var (
	shell32  = syscall.NewLazyDLL("shell32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	procExec = shell32.NewProc("ShellExecuteW")
	procMsg  = user32.NewProc("MessageBoxW")
)

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// msg: flags 0x24 = Si/No + pregunta; 0x40 = info; 0x10 = error. Devuelve 6 = Si.
func msg(text string, flags uintptr) uintptr {
	r, _, _ := procMsg.Call(0, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(appName))), flags)
	return r
}

func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func elevate() bool {
	exe, _ := os.Executable()
	args := strings.Join(os.Args[1:], " ")
	r, _, _ := procExec.Call(0, uintptr(unsafe.Pointer(u16("runas"))), uintptr(unsafe.Pointer(u16(exe))),
		uintptr(unsafe.Pointer(u16(args))), 0, 1)
	return r > 32
}

func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return c
}

func installDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, appName)
}

func shortcutPaths() (desktop, start string) {
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pub, "Desktop", appName+".lnk"),
		filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs`, appName+".lnk")
}

func makeShortcut(lnk, target, workdir string) error {
	c := hidden("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		`$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:S_LNK);$s.TargetPath=$env:S_TGT;`+
			`$s.WorkingDirectory=$env:S_DIR;$s.IconLocation=$env:S_TGT+',0';$s.Description='Mantenimiento y optimizacion del PC';$s.Save()`)
	c.Env = append(os.Environ(), "S_LNK="+lnk, "S_TGT="+target, "S_DIR="+workdir)
	return c.Run()
}

func install() {
	dir := installDir()
	if msg(fmt.Sprintf("¿Instalar %s %s en:\n\n%s\n\nSe crearán accesos directos en el Escritorio y en el menú Inicio.", appName, appVersion, dir), 0x24) != 6 {
		return
	}
	// cerrar una version anterior en ejecucion
	_ = hidden("taskkill", "/F", "/IM", exeName).Run()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		msg("No se pudo crear la carpeta de instalación:\n"+err.Error(), 0x10)
		return
	}
	exe := filepath.Join(dir, exeName)
	if err := os.WriteFile(exe, payload, 0o755); err != nil {
		msg("No se pudo copiar el programa:\n"+err.Error(), 0x10)
		return
	}
	self, _ := os.Executable()
	uninst := filepath.Join(dir, uninstName)
	if data, err := os.ReadFile(self); err == nil {
		_ = os.WriteFile(uninst, data, 0o755)
	}

	desk, start := shortcutPaths()
	var warns []string
	for _, l := range []string{desk, start} {
		if err := makeShortcut(l, exe, dir); err != nil {
			warns = append(warns, "No se pudo crear el acceso directo: "+l)
		}
	}

	size := fmt.Sprint((len(payload) + 1023) / 1024)
	reg := func(name, typ, val string) {
		_ = hidden("reg", "add", regKey, "/v", name, "/t", typ, "/d", val, "/f").Run()
	}
	reg("DisplayName", "REG_SZ", appName)
	reg("DisplayVersion", "REG_SZ", appVersion)
	reg("Publisher", "REG_SZ", publisher)
	reg("InstallLocation", "REG_SZ", dir)
	reg("DisplayIcon", "REG_SZ", exe)
	reg("UninstallString", "REG_SZ", `"`+uninst+`" /uninstall`)
	reg("NoModify", "REG_DWORD", "1")
	reg("NoRepair", "REG_DWORD", "1")
	reg("EstimatedSize", "REG_DWORD", size)

	text := appName + " se instaló correctamente.\n\n¿Quieres abrirlo ahora?"
	if len(warns) > 0 {
		text = strings.Join(warns, "\n") + "\n\n" + text
	}
	if msg(text, 0x24) == 6 {
		_ = exec.Command(exe).Start()
	}
}

func uninstall() {
	if msg("¿Desinstalar "+appName+" de este equipo?", 0x24) != 6 {
		return
	}
	_ = hidden("taskkill", "/F", "/IM", exeName).Run()
	desk, start := shortcutPaths()
	_ = os.Remove(desk)
	_ = os.Remove(start)
	_ = hidden("reg", "delete", regKey, "/f").Run()
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		_ = os.RemoveAll(filepath.Join(la, "OptimizadorPC")) // perfil de la ventana
	}
	dir := installDir()
	// El desinstalador se esta ejecutando desde dir: se borra la carpeta cuando termine.
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000,
		CmdLine: `cmd.exe /c ping 127.0.0.1 -n 3 >nul & rmdir /s /q "` + dir + `"`}
	_ = c.Start()
	msg(appName+" se desinstaló correctamente.", 0x40)
}

func main() {
	if !isAdmin() {
		if elevate() {
			return
		}
		msg("Se necesitan permisos de administrador para continuar.", 0x10)
		return
	}
	for _, a := range os.Args[1:] {
		if strings.EqualFold(a, "/uninstall") {
			uninstall()
			return
		}
	}
	install()
}
