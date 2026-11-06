//go:build windows

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

const sampleXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-06T12:00:00.123456700Z'/></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='IpAddress'>203.0.113.7</Data></EventData></Event>`

func fakeJob() *Job {
	ctx, c := context.WithCancel(context.Background())
	return &Job{ctx: ctx, cancelF: c}
}

func TestEventosFuerzaBruta(t *testing.T) {
	var all string
	for i := 0; i < 12; i++ {
		all += strings.Replace(sampleXML, "admin", "usuario"+string(rune('a'+i%6)), 1) + "\n"
	}
	all += `<Event xmlns='x'><System><EventID>1102</EventID><TimeCreated SystemTime='2026-11-06T12:05:00Z'/></System><EventData><Data Name='SubjectUserName'>mallory</Data></EventData></Event>`
	all += `<Event xmlns='x'><System><EventID>4732</EventID><TimeCreated SystemTime='2026-11-06T12:06:00Z'/></System><EventData><Data Name='TargetSid'>S-1-5-32-544</Data><Data Name='MemberName'>CN=eve</Data><Data Name='SubjectUserName'>mallory</Data></EventData></Event>`
	ev := parseEventos(all, "Security")
	if len(ev) != 14 {
		t.Fatalf("eventos parseados = %d, esperado 14", len(ev))
	}
	al, cnt := analizarEventos(ev)
	if cnt["4625"] != 12 {
		t.Fatalf("conteo 4625 = %d", cnt["4625"])
	}
	has := func(sub string) bool {
		for _, a := range al {
			if strings.Contains(a.Titulo, sub) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{"fuerza bruta", "password spraying", "registro de auditoría", "Administradores"} {
		if !has(s) {
			t.Errorf("falta alerta %q; hay %+v", s, al)
		}
	}
}

func TestEventosSinAlerta(t *testing.T) {
	ev := parseEventos(sampleXML, "Security")
	if al, _ := analizarEventos(ev); len(al) != 0 {
		t.Fatalf("un solo fallo no debe alertar: %+v", al)
	}
}

func TestExeDeComando(t *testing.T) {
	os.Setenv("FOO", `C:\Datos`)
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" /min`: `C:\Program Files\App\app.exe`,
		`C:\Tools\x.exe -a -b`:                `C:\Tools\x.exe`,
		`%FOO%\y.exe --z`:                     `C:\Datos\y.exe`,
	}
	for in, want := range cases {
		if got := exeDeComando(in); got != want {
			t.Errorf("exeDeComando(%q) = %q, esperado %q", in, got, want)
		}
	}
}

func TestAnalizarPropioEjecutable(t *testing.T) {
	exe, _ := os.Executable()
	a, err := analizarArchivo(fakeJob(), exe, "test.exe", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.PE == nil || a.PE.Maquina != "x64" || len(a.PE.Secciones) == 0 {
		t.Fatalf("PE no analizado: %+v", a.PE)
	}
	if len(a.SHA256) != 64 || a.Entropia <= 0 || a.Tipo != "Ejecutable de Windows (PE)" {
		t.Fatalf("datos básicos incorrectos: %+v", a)
	}
	if !strings.Contains(a.Yara, "rule ") || !strings.Contains(a.Yara, "condition:") {
		t.Fatalf("YARA sin forma: %s", a.Yara)
	}
	for _, h := range a.Hallazgos {
		t.Logf("  [%s] %+d %s", h.Tipo, h.Peso, h.Texto)
	}
	t.Logf("sha256=%s entropia=%.2f secciones=%d importes=%d veredicto=%s cadenas=%d", a.SHA256, a.Entropia, len(a.PE.Secciones), a.PE.Importes, a.Veredicto, a.Cadenas.Total)
}

func TestAnalizarScriptSospechoso(t *testing.T) {
	f, _ := os.CreateTemp("", "mal*.ps1")
	f.WriteString("powershell -w hidden -enc SQBFAFgA\r\ncmd /c vssadmin delete shadows /all /quiet\r\nreg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v x\r\nhttp://203.0.113.9/payload.bin\r\n")
	f.Close()
	defer os.Remove(f.Name())
	a, err := analizarArchivo(fakeJob(), f.Name(), "mal.ps1", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Veredicto == "bajo" || len(a.Cadenas.Comandos) == 0 || len(a.Cadenas.URLs) != 1 || len(a.Cadenas.IPs) != 1 {
		t.Fatalf("no detectó indicadores: veredicto=%s %+v", a.Veredicto, a.Cadenas)
	}
	t.Logf("veredicto=%s score=%d hallazgos=%d", a.Veredicto, a.Score, len(a.Hallazgos))
}

func TestAnalizarTextoInocuo(t *testing.T) {
	f, _ := os.CreateTemp("", "ok*.txt")
	f.WriteString("Lista de compras: pan, leche y huevos.\n")
	f.Close()
	defer os.Remove(f.Name())
	a, _ := analizarArchivo(fakeJob(), f.Name(), "ok.txt", true)
	if a.Veredicto != "bajo" || a.Score != 0 {
		t.Fatalf("falso positivo: %s %d %+v", a.Veredicto, a.Score, a.Hallazgos)
	}
}

func TestConexionesYAuditoria(t *testing.T) {
	c := listarConexiones()
	t.Logf("conexiones: %d", len(c))
	chk := ejecutarAuditoria()
	if len(chk) < 5 {
		t.Fatalf("auditoría devolvió %d comprobaciones", len(chk))
	}
	for _, x := range chk {
		t.Logf("%-10s %-5s %s", x.ID, x.Status, x.Detail)
	}
}

func TestAnalizarDist(t *testing.T) {
	p := os.Getenv("OPT_ANALIZAR")
	if p == "" {
		t.Skip("sin OPT_ANALIZAR")
	}
	a, err := analizarArchivo(fakeJob(), p, "x.exe", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range a.Hallazgos {
		t.Logf("  [%s] %+d %s", h.Tipo, h.Peso, h.Texto)
	}
	t.Logf("veredicto=%s score=%d", a.Veredicto, a.Score)
}
