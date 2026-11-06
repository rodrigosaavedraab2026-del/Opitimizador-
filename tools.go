//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ------------------------------------------------------------ carpetas y rutas permitidas

type carpeta struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func carpetasUsuario() []carpeta {
	prof := env("USERPROFILE")
	var out []carpeta
	add := func(n, p string) {
		if p == "" {
			return
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, carpeta{n, p})
		}
	}
	add("Mi perfil (todo)", prof)
	add("Descargas", join(prof, "Downloads"))
	add("Documentos", join(prof, "Documents"))
	add("Escritorio", join(prof, "Desktop"))
	add("Imágenes", join(prof, "Pictures"))
	add("Vídeos", join(prof, "Videos"))
	add("Música", join(prof, "Music"))
	for _, d := range fixedDisks() {
		add("Disco "+d.Letter+" completo", d.Letter+`\`)
	}
	return out
}

var (
	allowMu sync.Mutex
	allowed = map[string]bool{}
)

func setAllowed(paths []string) {
	allowMu.Lock()
	defer allowMu.Unlock()
	for _, p := range paths {
		allowed[strings.ToLower(filepath.Clean(p))] = true
	}
}
func isAllowed(p string) bool {
	allowMu.Lock()
	defer allowMu.Unlock()
	return allowed[strings.ToLower(filepath.Clean(p))]
}

// zonaProtegida: nunca se analizan ni se mandan a la papelera archivos del sistema.
func zonaProtegida(p string) bool {
	low := strings.ToLower(filepath.Clean(p))
	for _, e := range []string{"WINDIR", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"} {
		if v := env(e); v != "" && (low == strings.ToLower(v) || strings.HasPrefix(low, strings.ToLower(v)+`\`)) {
			return true
		}
	}
	for _, s := range []string{`\$recycle.bin`, `\system volume information`, `\windowsapps`} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

func validarRaiz(root string) (string, error) {
	r := filepath.Clean(root)
	st, err := os.Stat(r)
	if err != nil || !st.IsDir() {
		return "", errors.New("la carpeta no existe")
	}
	return r, nil
}

// ------------------------------------------------------------ archivos grandes

type bigFile struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

func scanBigFiles(j *Job, root string, minBytes int64) {
	j.log("Analizando " + root + " ...")
	var found []bigFile
	var count int64
	last := time.Now()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if j.ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if zonaProtegida(p) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		count++
		if time.Since(last) > 1500*time.Millisecond {
			j.progress(fmt.Sprintf("%d archivos revisados…", count))
			last = time.Now()
		}
		info, e := d.Info()
		if e != nil || info.Size() < minBytes {
			return nil
		}
		found = append(found, bigFile{p, info.Size(), info.ModTime().Unix()})
		if len(found) > 4000 {
			sort.Slice(found, func(a, b int) bool { return found[a].Size > found[b].Size })
			found = found[:500]
		}
		return nil
	})
	sort.Slice(found, func(a, b int) bool { return found[a].Size > found[b].Size })
	if len(found) > 150 {
		found = found[:150]
	}
	paths := make([]string, len(found))
	for i, f := range found {
		paths[i] = f.Path
	}
	setAllowed(paths)
	j.setResult(map[string]interface{}{"files": found, "scanned": count})
	j.log(fmt.Sprintf("[OK] %d archivos revisados; mostrando los %d más grandes.", count, len(found)))
}

// ------------------------------------------------------------ duplicados

type dupFile struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime"`
}
type dupGroup struct {
	Size  int64     `json:"size"`
	Files []dupFile `json:"files"`
}

func hashFile(p string, limit int64) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	var r io.Reader = f
	if limit > 0 {
		r = io.LimitReader(f, limit)
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scanDuplicates(j *Job, root string, minBytes int64) {
	j.log("Buscando archivos repetidos en " + root + " ...")
	bySize := map[int64][]string{}
	var count int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if j.ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if zonaProtegida(p) || strings.EqualFold(d.Name(), "AppData") || strings.EqualFold(d.Name(), "node_modules") || strings.EqualFold(d.Name(), ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() < minBytes {
			return nil
		}
		count++
		bySize[info.Size()] = append(bySize[info.Size()], p)
		return nil
	})
	j.log(fmt.Sprintf("%d archivos candidatos. Comparando contenido...", count))
	var groups []dupGroup
	done := 0
	for size, list := range bySize {
		if j.ctx.Err() != nil {
			break
		}
		if len(list) < 2 {
			continue
		}
		done++
		if done%20 == 0 {
			j.progress(fmt.Sprintf("Comparando grupos… %d", done))
		}
		// 1) hash parcial (primeros 64 KB) 2) hash completo solo si coincide
		part := map[string][]string{}
		for _, p := range list {
			if h, err := hashFile(p, 64*1024); err == nil {
				part[h] = append(part[h], p)
			}
		}
		for _, cand := range part {
			if len(cand) < 2 {
				continue
			}
			full := map[string][]string{}
			for _, p := range cand {
				if h, err := hashFile(p, 0); err == nil {
					full[h] = append(full[h], p)
				}
			}
			for _, same := range full {
				if len(same) < 2 {
					continue
				}
				g := dupGroup{Size: size}
				for _, p := range same {
					var mt int64
					if st, err := os.Stat(p); err == nil {
						mt = st.ModTime().Unix()
					}
					g.Files = append(g.Files, dupFile{p, mt})
				}
				sort.Slice(g.Files, func(a, b int) bool { return g.Files[a].MTime < g.Files[b].MTime })
				groups = append(groups, g)
			}
		}
	}
	sort.Slice(groups, func(a, b int) bool {
		return groups[a].Size*int64(len(groups[a].Files)-1) > groups[b].Size*int64(len(groups[b].Files)-1)
	})
	if len(groups) > 200 {
		groups = groups[:200]
	}
	var all []string
	var wasted int64
	for _, g := range groups {
		wasted += g.Size * int64(len(g.Files)-1)
		for _, f := range g.Files {
			all = append(all, f.Path)
		}
	}
	setAllowed(all)
	j.setResult(map[string]interface{}{"groups": groups, "wasted": wasted})
	j.log(fmt.Sprintf("[OK] %d grupos de archivos repetidos. Espacio recuperable: %s", len(groups), fmtSize(wasted)))
}

// papelera: solo rutas devueltas por un analisis previo, fuera de zonas del sistema.
func enviarAPapelera(paths []string) (int, error) {
	var ok []string
	for _, p := range paths {
		if !isAllowed(p) || zonaProtegida(p) {
			continue
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		ok = append(ok, filepath.Clean(p))
	}
	if len(ok) == 0 {
		return 0, errors.New("ningún archivo válido para eliminar")
	}
	if err := moveToRecycleBin(ok); err != nil {
		return 0, err
	}
	return len(ok), nil
}

func mostrarEnExplorador(p string) error {
	if !isAllowed(p) {
		return errors.New("ruta no permitida")
	}
	return revealInExplorer(filepath.Clean(p))
}

// ------------------------------------------------------------ ajustes de Windows (registro)

type regEntry struct {
	Root   registry.Key
	Path   string
	Name   string
	String bool
	On     interface{} // valor cuando el ajuste esta ACTIVADO
	Off    interface{}
	Absent bool // si falta el valor, cuenta como ACTIVADO
}

type setting struct {
	ID, Name, Desc, Note string
	Admin                bool
	Entries              []regEntry
	special              string
}

const (
	cvPath  = `SOFTWARE\Microsoft\Windows\CurrentVersion`
	cdmPath = cvPath + `\ContentDeliveryManager`
	advPath = cvPath + `\Explorer\Advanced`
)

func catalogoAjustes() []setting {
	cu, lm := registry.CURRENT_USER, registry.LOCAL_MACHINE
	return []setting{
		{ID: "adid", Name: "Desactivar ID de publicidad", Desc: "Evita que las apps te sigan para mostrar anuncios personalizados.",
			Entries: []regEntry{{Root: cu, Path: cvPath + `\AdvertisingInfo`, Name: "Enabled", On: uint32(0), Off: uint32(1)}}},
		{ID: "tips", Name: "Quitar sugerencias y anuncios de Windows", Desc: "Oculta consejos, apps sugeridas y promociones en Inicio y pantalla de bloqueo.",
			Entries: []regEntry{
				{Root: cu, Path: cdmPath, Name: "SubscribedContent-338388Enabled", On: uint32(0), Off: uint32(1)},
				{Root: cu, Path: cdmPath, Name: "SubscribedContent-338389Enabled", On: uint32(0), Off: uint32(1)},
				{Root: cu, Path: cdmPath, Name: "SubscribedContent-310093Enabled", On: uint32(0), Off: uint32(1)},
				{Root: cu, Path: cdmPath, Name: "SystemPaneSuggestionsEnabled", On: uint32(0), Off: uint32(1)}}},
		{ID: "bing", Name: "Búsqueda del Inicio solo local", Desc: "Quita resultados de Bing al buscar en el menú Inicio.", Note: "Requiere reiniciar el Explorador.",
			Entries: []regEntry{{Root: cu, Path: `SOFTWARE\Policies\Microsoft\Windows\Explorer`, Name: "DisableSearchBoxSuggestions", On: uint32(1), Off: uint32(0)}}},
		{ID: "transp", Name: "Desactivar efectos de transparencia", Desc: "Menos carga gráfica en equipos modestos.",
			Entries: []regEntry{{Root: cu, Path: cvPath + `\Themes\Personalize`, Name: "EnableTransparency", On: uint32(0), Off: uint32(1)}}},
		{ID: "anim", Name: "Desactivar animaciones de ventanas", Desc: "Minimizar y maximizar sin animación.", Note: "Se aplica al volver a iniciar sesión.",
			Entries: []regEntry{{Root: cu, Path: `Control Panel\Desktop\WindowMetrics`, Name: "MinAnimate", String: true, On: "0", Off: "1"}}},
		{ID: "gamemode", Name: "Modo juego", Desc: "Prioriza el juego en primer plano.",
			Entries: []regEntry{{Root: cu, Path: `SOFTWARE\Microsoft\GameBar`, Name: "AutoGameModeEnabled", On: uint32(1), Off: uint32(0), Absent: true}}},
		{ID: "ext", Name: "Mostrar extensiones de archivo", Desc: "Ver .exe, .pdf, etc. Ayuda a detectar archivos engañosos.", Note: "Reinicia el Explorador para verlo.",
			Entries: []regEntry{{Root: cu, Path: advPath, Name: "HideFileExt", On: uint32(0), Off: uint32(1)}}},
		{ID: "hidden", Name: "Mostrar archivos ocultos", Desc: "Muestra carpetas y archivos ocultos en el Explorador.", Note: "Reinicia el Explorador para verlo.",
			Entries: []regEntry{{Root: cu, Path: advPath, Name: "Hidden", On: uint32(1), Off: uint32(2)}}},
		{ID: "faststart", Name: "Inicio rápido", Desc: "Arranque más veloz usando hibernación parcial. Desactívalo si el equipo falla al reiniciar o apagar.", Admin: true,
			Entries: []regEntry{{Root: lm, Path: `SYSTEM\CurrentControlSet\Control\Session Manager\Power`, Name: "HiberbootEnabled", On: uint32(1), Off: uint32(0)}}},
		{ID: "hibernate", Name: "Hibernación", Desc: "Si la desactivas se libera el archivo hiberfil.sys (varios GB).", Admin: true, special: "hibernate"},
	}
}

func regEntryIs(e regEntry, wantOn bool) bool {
	want := e.Off
	if wantOn {
		want = e.On
	}
	if e.String {
		v := regStr(e.Root, e.Path, e.Name)
		if v == "" && e.Absent {
			return wantOn
		}
		return v == want.(string)
	}
	v, ok := regDword(e.Root, e.Path, e.Name)
	if !ok {
		if e.Absent {
			return wantOn
		}
		return !wantOn
	}
	return v == want.(uint32)
}

func ajusteActivo(s setting) bool {
	if s.special == "hibernate" {
		v, ok := regDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled")
		return ok && v == 1
	}
	for _, e := range s.Entries {
		if !regEntryIs(e, true) {
			return false
		}
	}
	return true
}

type ajusteOut struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Note  string `json:"note"`
	On    bool   `json:"on"`
	Admin bool   `json:"admin"`
}

func listAjustes() []ajusteOut {
	var out []ajusteOut
	for _, s := range catalogoAjustes() {
		on := ajusteActivo(s)
		if s.special == "hibernate" { // en la UI: "activado" = hibernacion encendida
			out = append(out, ajusteOut{s.ID, s.Name, s.Desc, s.Note, on, s.Admin})
			continue
		}
		out = append(out, ajusteOut{s.ID, s.Name, s.Desc, s.Note, on, s.Admin})
	}
	return out
}

func setAjuste(id string, on bool) error {
	for _, s := range catalogoAjustes() {
		if s.ID != id {
			continue
		}
		if s.special == "hibernate" {
			arg := "off"
			if on {
				arg = "on"
			}
			out, err := nativeOutput(30*time.Second, "powercfg", "/hibernate", arg)
			if err != nil {
				return fmt.Errorf("powercfg: %s", strings.TrimSpace(out))
			}
			return nil
		}
		for _, e := range s.Entries {
			k, _, err := registry.CreateKey(e.Root, e.Path, registry.SET_VALUE)
			if err != nil {
				return err
			}
			v := e.Off
			if on {
				v = e.On
			}
			if e.String {
				err = k.SetStringValue(e.Name, v.(string))
			} else {
				err = k.SetDWordValue(e.Name, v.(uint32))
			}
			k.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("ajuste desconocido")
}

// Para ajustes con semantica "activado = protegido" el interruptor muestra el estado real del registro.

// ------------------------------------------------------------ red

type netAdapter struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac"`
	Addrs []string `json:"addrs"`
	MTU   int      `json:"mtu"`
}

func listAdapters() []netAdapter {
	out := []netAdapter{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := netAdapter{Name: i.Name, MAC: i.HardwareAddr.String(), MTU: i.MTU, Addrs: []string{}}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			a.Addrs = append(a.Addrs, ad.String())
		}
		out = append(out, a)
	}
	return out
}

type netTest struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	MS     int64  `json:"ms"`
	Detail string `json:"detail"`
}

func testRed() []netTest {
	res := make([]netTest, 5)
	var wg sync.WaitGroup
	run := func(i int, name string, fn func() (string, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			d, err := fn()
			res[i] = netTest{Name: name, OK: err == nil, MS: time.Since(t0).Milliseconds(), Detail: d}
			if err != nil {
				res[i].Detail = err.Error()
			}
		}()
	}
	dial := func(addr string) func() (string, error) {
		return func() (string, error) {
			c, err := net.DialTimeout("tcp", addr, 4*time.Second)
			if err != nil {
				return "", err
			}
			c.Close()
			return addr, nil
		}
	}
	run(0, "Conexión a Cloudflare (1.1.1.1)", dial("1.1.1.1:443"))
	run(1, "Conexión a Google (8.8.8.8)", dial("8.8.8.8:443"))
	run(2, "Resolución DNS (www.microsoft.com)", func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupHost(ctx, "www.microsoft.com")
		if err != nil {
			return "", err
		}
		return ips[0], nil
	})
	run(3, "Internet (prueba de Windows)", func() (string, error) {
		cl := http.Client{Timeout: 5 * time.Second}
		r, err := cl.Get("http://www.msftconnecttest.com/connecttest.txt")
		if err != nil {
			return "", err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64))
		if !strings.Contains(string(b), "Microsoft Connect Test") {
			return "", errors.New("respuesta inesperada (¿portal cautivo?)")
		}
		return "Conectado", nil
	})
	run(4, "Puerta de enlace / adaptadores", func() (string, error) {
		a := listAdapters()
		if len(a) == 0 {
			return "", errors.New("no hay adaptadores de red activos")
		}
		return fmt.Sprintf("%d adaptador(es) activo(s)", len(a)), nil
	})
	wg.Wait()
	return res
}

func runRedFix(j *Job, ids []string) {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	j.log("== REPARACIÓN DE RED ==")
	steps := []struct {
		id, title, exe string
		args           []string
	}{
		{"dns", "Vaciar caché DNS", "ipconfig", []string{"/flushdns"}},
		{"renew", "Renovar dirección IP", "cmd.exe", []string{"/c", "ipconfig /release & ipconfig /renew"}},
		{"winsock", "Restablecer Winsock (requiere reiniciar)", "netsh", []string{"winsock", "reset"}},
		{"iprst", "Restablecer pila TCP/IP (requiere reiniciar)", "netsh", []string{"int", "ip", "reset"}},
	}
	for _, s := range steps {
		if !sel[s.id] || j.cancelled() {
			continue
		}
		j.log(">> " + s.title)
		if err := runNative(j, s.exe, s.args...); err != nil {
			j.log("[!!] " + s.title + ": " + err.Error())
		} else {
			j.log("[OK] " + s.title)
		}
	}
	j.log("[OK] FINALIZADO")
}

// ------------------------------------------------------------ salud de discos (PowerShell, opcional)

func saludDiscos() interface{} {
	out, err := psOutput(`
$l = @(Get-PhysicalDisk | ForEach-Object { [pscustomobject]@{ nombre=[string]$_.FriendlyName; tipo=[string]$_.MediaType; estado=[string]$_.HealthStatus; bytes=[double]$_.Size } })
ConvertTo-Json -InputObject $l -Compress`, nil)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	var v []interface{}
	if json.Unmarshal([]byte(out), &v) != nil {
		return map[string]string{"error": "respuesta inesperada"}
	}
	return v
}
