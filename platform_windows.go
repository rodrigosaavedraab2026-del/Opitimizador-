//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	shell32  = syscall.NewLazyDLL("shell32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procShellExecuteW      = shell32.NewProc("ShellExecuteW")
	procMessageBoxW        = user32.NewProc("MessageBoxW")
	procMultiByteToWideChr = kernel32.NewProc("MultiByteToWideChar")
)

const createNoWindow = 0x08000000

func utf16p(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

// isAdmin: intenta abrir el disco fisico 0, algo que solo puede un administrador elevado.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// elevate relanza este mismo .exe pidiendo UAC. Devuelve true si el usuario acepto.
func elevate() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	args := strings.Join(os.Args[1:], " ")
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(utf16p("runas"))),
		uintptr(unsafe.Pointer(utf16p(exe))), uintptr(unsafe.Pointer(utf16p(args))), 0, 1)
	return r > 32
}

func showMessage(title, msg string) {
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16p(msg))), uintptr(unsafe.Pointer(utf16p(title))), 0x10)
}

func openWindow(url string) {
	local := os.Getenv("LOCALAPPDATA")
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	cands := []string{
		filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
	}
	profile := filepath.Join(local, "OptimizadorPC", "perfil")
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			cmd := exec.Command(c, "--app="+url, "--window-size=1120,780", "--no-first-run",
				"--user-data-dir="+profile)
			if cmd.Start() == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func psCommand(script string, envv map[string]string, utf8 bool) *exec.Cmd {
	pre := "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';"
	if utf8 {
		pre += "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
	}
	u16 := utf16.Encode([]rune(pre + script))
	buf := make([]byte, 0, len(u16)*2)
	for _, v := range u16 {
		buf = append(buf, byte(v), byte(v>>8))
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(buf))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	cmd.Env = os.Environ()
	for k, v := range envv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}

// psOutput ejecuta PowerShell y devuelve su salida (UTF-8).
func psOutput(script string, envv map[string]string) (string, error) {
	cmd := psCommand(script, envv, true)
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

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		return s[:i]
	}
	return s
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
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	sc.Split(splitCRLF)
	for sc.Scan() {
		b := sc.Bytes()
		line := string(b)
		if oem {
			line = decodeOEM(b)
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || progressBar.MatchString(line) {
			continue
		}
		j.log("  " + line)
	}
	return cmd.Wait()
}

func runPS(j *Job, script string, envv map[string]string) error {
	return stream(j, psCommand(script, envv, true), false)
}

func runNative(j *Job, exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return stream(j, cmd, true)
}

// decodeOEM convierte la salida de herramientas de consola (pagina de codigos OEM) a UTF-8.
func decodeOEM(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n, _, _ := procMultiByteToWideChr.Call(1, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	procMultiByteToWideChr.Call(1, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&w[0])), n)
	return string(utf16.Decode(w))
}

var reMsi = regexp.MustCompile(`(?i)^\s*"?(?:[^"]*\\)?msiexec(?:\.exe)?"?\s*`)

// lanzarDesinstalador inicia el desinstalador registrado (sin esperar a que termine).
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
