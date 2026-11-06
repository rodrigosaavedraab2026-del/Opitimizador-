//go:build windows

// Optimizador PC: aplicacion de mantenimiento y optimizacion para Windows.
// Un unico .exe: levanta un servidor SOLO local (127.0.0.1) con la interfaz embebida
// y abre una ventana de Edge/Chrome en modo "app".
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

var (
	token    string
	hostPort string

	lastPing   = time.Now()
	pingMu     sync.Mutex
	pingedOnce bool
	byeAt      time.Time
)

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// guard: solo acepta el Host local correcto (anti DNS-rebinding), Origin propio en POST (anti CSRF)
// y rutas bajo el prefijo secreto /<token>/.
func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != hostPort {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+hostPort {
				http.Error(w, "origen no permitido", http.StatusForbidden)
				return
			}
		}
		h(w, r)
	}
}

func main() {
	noElev := false
	for _, a := range os.Args[1:] {
		if a == "--no-elevate" {
			noElev = true
		}
	}
	if !noElev && !isAdmin() {
		if elevate() {
			return
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("No se pudo abrir el puerto local: " + err.Error())
	}
	hostPort = ln.Addr().String()
	token = newToken()
	for _, a := range os.Args[1:] {
		if a == "--test-token" {
			token = "test"
		}
	}

	base := "/" + token
	mux := http.NewServeMux()
	mux.HandleFunc(base+"/", guard(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != base+"/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		_, _ = w.Write(indexHTML)
	}))
	registerAPI(mux, base)

	url := "http://" + hostPort + base + "/"
	if !hasArg("--no-window") {
		go func() { time.Sleep(300 * time.Millisecond); openWindow(url) }()
	}
	go watchdog()

	fmt.Println("Optimizador PC en", url)
	if err := http.Serve(ln, mux); err != nil {
		fatal(err.Error())
	}
}

func hasArg(a string) bool {
	for _, x := range os.Args[1:] {
		if x == a {
			return true
		}
	}
	return false
}

// El programa termina cuando se cierra la ventana: aviso explicito (/bye) o latido perdido.
// Nunca termina mientras haya una tarea en ejecucion.
func watchdog() {
	for {
		time.Sleep(2 * time.Second)
		if jobsRunning() > 0 {
			continue
		}
		pingMu.Lock()
		idle := time.Since(lastPing)
		seen := pingedOnce
		bye := !byeAt.IsZero() && byeAt.After(lastPing) && time.Since(byeAt) > 4*time.Second
		pingMu.Unlock()
		// Chrome/Edge frenan los temporizadores de ventanas minimizadas (1 vez/min): margen amplio.
		if bye || (seen && idle > 4*time.Minute) || (!seen && idle > 2*time.Minute) {
			os.Exit(0)
		}
	}
}

func fatal(msg string) {
	showMessage("Optimizador PC", msg)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func decode(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != http.MethodPost {
		writeErr(w, 400, "petición inválida")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if json.NewDecoder(r.Body).Decode(v) != nil {
		writeErr(w, 400, "petición inválida")
		return false
	}
	return true
}

func registerAPI(mux *http.ServeMux, base string) {
	api := func(path string, h http.HandlerFunc) { mux.HandleFunc(base+"/api/"+path, guard(h)) }

	api("ping", func(w http.ResponseWriter, r *http.Request) {
		pingMu.Lock()
		lastPing, pingedOnce = time.Now(), true
		pingMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": true, "admin": isAdmin()})
	})
	api("bye", func(w http.ResponseWriter, r *http.Request) {
		pingMu.Lock()
		byeAt = time.Now()
		pingMu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})

	// ---- panel / sistema
	api("live", func(w http.ResponseWriter, r *http.Request) {
		total, avail := memInfo()
		writeJSON(w, map[string]interface{}{"cpu": cpuPercent(), "ramTotal": total, "ramLibre": avail,
			"horas": uptimeSeconds() / 3600, "discos": fixedDisks(), "procesos": len(snapshotProcs())})
	})
	api("info", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, systemInfo()) })
	api("health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, saludDiscos()) })
	api("folders", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, carpetasUsuario()) })

	// ---- limpieza / optimizacion / reparacion / red (tareas con registro en vivo)
	jobAPI := func(path string, fn func(*Job, []string)) {
		api(path, func(w http.ResponseWriter, r *http.Request) {
			var b struct {
				Items []string `json:"items"`
			}
			if !decode(w, r, &b) {
				return
			}
			writeJSON(w, map[string]string{"job": startJob(func(j *Job) { fn(j, b.Items) })})
		})
	}
	api("scan", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, scanLimpieza()) })
	jobAPI("clean", runLimpieza)
	jobAPI("optimize", runOptimizar)
	jobAPI("repair", runReparar)
	jobAPI("netfix", runRedFix)
	api("job", func(w http.ResponseWriter, r *http.Request) {
		j := getJob(r.URL.Query().Get("id"))
		if j == nil {
			writeErr(w, 404, "tarea no encontrada")
			return
		}
		from := 0
		fmt.Sscanf(r.URL.Query().Get("from"), "%d", &from)
		writeJSON(w, j.snapshot(from))
	})
	api("cancel", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &b) {
			return
		}
		if j := getJob(b.ID); j != nil {
			j.cancel()
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// ---- inicio / programas / tienda / usuarios
	api("startup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var b struct {
				Scope   string `json:"scope"`
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			}
			if !decode(w, r, &b) {
				return
			}
			if err := setStartupEnabled(b.Scope, b.Name, b.Enabled); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, listStartup())
	})
	api("programs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, listProgramas()) })
	api("uninstall", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &b) {
			return
		}
		msg, err := desinstalar(b.ID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"msg": msg})
	})
	api("appx", func(w http.ResponseWriter, r *http.Request) {
		l, err := listAppx()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, l)
	})
	api("appxremove", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &b) {
			return
		}
		if err := quitarAppx(b.ID); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("users", func(w http.ResponseWriter, r *http.Request) {
		l, err := listUsuarios()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, l)
	})
	api("makeadmin", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			User string `json:"user"`
		}
		if !decode(w, r, &b) {
			return
		}
		msg, err := hacerAdmin(b.User)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"msg": msg})
	})

	// ---- procesos / servicios
	api("procs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, listProcesses()) })
	api("killproc", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			PID  uint32 `json:"pid"`
			Name string `json:"name"`
		}
		if !decode(w, r, &b) {
			return
		}
		if err := killProcess(b.PID, b.Name); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("services", func(w http.ResponseWriter, r *http.Request) {
		l, err := listServices()
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, l)
	})
	api("service", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Name, Action string }
		if !decode(w, r, &b) {
			return
		}
		if err := serviceAction(b.Name, b.Action); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// ---- archivos grandes / duplicados
	scanAPI := func(path string, fn func(*Job, string, int64)) {
		api(path, func(w http.ResponseWriter, r *http.Request) {
			var b struct {
				Root  string `json:"root"`
				MinMB int64  `json:"minMB"`
			}
			if !decode(w, r, &b) {
				return
			}
			root, err := validarRaiz(b.Root)
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			min := b.MinMB * 1024 * 1024
			writeJSON(w, map[string]string{"job": startJob(func(j *Job) { fn(j, root, min) })})
		})
	}
	scanAPI("bigfiles", scanBigFiles)
	scanAPI("dupes", scanDuplicates)
	api("trash", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Paths []string `json:"paths"`
		}
		if !decode(w, r, &b) {
			return
		}
		n, err := enviarAPapelera(b.Paths)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]int{"n": n})
	})
	api("reveal", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Path string `json:"path"`
		}
		if !decode(w, r, &b) {
			return
		}
		if err := mostrarEnExplorador(b.Path); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// ---- ajustes de Windows / red
	api("settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var b struct {
				ID string `json:"id"`
				On bool   `json:"on"`
			}
			if !decode(w, r, &b) {
				return
			}
			if err := setAjuste(b.ID, b.On); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, listAjustes())
	})
	api("restartexplorer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "método no permitido")
			return
		}
		if err := restartExplorer(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("net", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, listAdapters()) })

	// ---- seguridad defensiva
	api("secaudit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) { j.setResult(ejecutarAuditoria()) })})
	})
	api("secfix", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &b) {
			return
		}
		msg, err := corregirAuditoria(b.ID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"msg": msg})
	})
	api("persist", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) { j.setResult(buscarPersistencia(j)) })})
	})
	api("taskoff", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Tarea string `json:"tarea"`
		}
		if !decode(w, r, &b) {
			return
		}
		if err := desactivarTarea(b.Tarea); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("events", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Horas int `json:"horas"`
		}
		if !decode(w, r, &b) {
			return
		}
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) { j.setResult(leerEventosSeguridad(j, b.Horas)) })})
	})
	api("auditlogon", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "método no permitido")
			return
		}
		if err := activarAuditoriaLogon(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	api("analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "método no permitido")
			return
		}
		var ruta, nombre, tmp string
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var b struct {
				Path string `json:"path"`
			}
			if !decode(w, r, &b) {
				return
			}
			ruta = filepath.Clean(strings.Trim(strings.TrimSpace(b.Path), `"`))
			if st, err := os.Stat(ruta); err != nil || st.IsDir() {
				writeErr(w, 400, "esa ruta no es un archivo")
				return
			}
			nombre = filepath.Base(ruta)
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, 300<<20)
			nombre = safeName(r.URL.Query().Get("name"))
			dir, err := os.MkdirTemp("", "OptimizadorPC-analisis-")
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			tmp = dir
			ruta = filepath.Join(dir, nombre)
			f, err := os.Create(ruta)
			if err == nil {
				_, err = io.Copy(f, r.Body)
				f.Close()
			}
			if err != nil {
				os.RemoveAll(dir)
				writeErr(w, 400, "no se pudo recibir el archivo (máximo 300 MB): "+err.Error())
				return
			}
		}
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) {
			if tmp != "" {
				defer os.RemoveAll(tmp)
			}
			j.log("Analizando " + nombre + " (el archivo no se ejecuta)...")
			a, err := analizarArchivo(j, ruta, nombre, tmp != "")
			if err != nil {
				j.log("[XX] " + err.Error())
				return
			}
			j.setResult(a)
			j.log("[OK] Análisis completado.")
		})})
	})
	api("nettest", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, testRed()) })
}

// ---------------------------------------------------------------- tareas

type Job struct {
	mu      sync.Mutex
	lines   []string
	done    bool
	prog    string
	result  interface{}
	ctx     context.Context
	cancelF context.CancelFunc
}

var (
	jobs   = map[string]*Job{}
	jobsMu sync.Mutex
)

func startJob(fn func(*Job)) string {
	id := newToken()[:12]
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{ctx: ctx, cancelF: cancel}
	jobsMu.Lock()
	jobs[id] = j
	jobsMu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				j.log(fmt.Sprintf("[XX] error interno: %v", r))
			}
			j.mu.Lock()
			j.done = true
			j.mu.Unlock()
		}()
		fn(j)
	}()
	return id
}

func getJob(id string) *Job {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	return jobs[id]
}

func jobsRunning() int {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	n := 0
	for _, j := range jobs {
		j.mu.Lock()
		if !j.done {
			n++
		}
		j.mu.Unlock()
	}
	return n
}

func (j *Job) log(s string) {
	j.mu.Lock()
	j.lines = append(j.lines, strings.TrimRight(s, "\r\n"))
	j.mu.Unlock()
}
func (j *Job) progress(s string)       { j.mu.Lock(); j.prog = s; j.mu.Unlock() }
func (j *Job) setResult(v interface{}) { j.mu.Lock(); j.result = v; j.mu.Unlock() }
func (j *Job) cancel()                 { j.cancelF() }
func (j *Job) cancelled() bool         { return j.ctx.Err() != nil }

func (j *Job) snapshot(from int) map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	if from < 0 || from > len(j.lines) {
		from = 0
	}
	lines := append([]string{}, j.lines[from:]...)
	m := map[string]interface{}{"lines": lines, "next": len(j.lines), "done": j.done, "progress": j.prog}
	if j.done {
		m["result"] = j.result
		m["cancelled"] = j.ctx.Err() != nil
	}
	return m
}

func safeName(n string) string {
	n = filepath.Base(strings.TrimSpace(n))
	n = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < 32 {
			return '_'
		}
		return r
	}, n)
	if n == "" || n == "." || n == ".." {
		n = "muestra.bin"
	}
	return n
}
