// Optimizador PC - aplicacion de mantenimiento y optimizacion para Windows.
//
// Es un unico .exe: levanta un servidor SOLO local (127.0.0.1) con una
// interfaz grafica embebida y abre una ventana de Edge/Chrome en modo "app".
// Basado en los scripts PowerShell de mantenimiento (diagnostico, limpieza,
// desinstalar, optimizar, permisos de administrador).
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
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
	w.WriteHeader(code)
	writeJSON(w, map[string]string{"error": msg})
}

// guard: solo acepta peticiones con el Host local correcto (anti DNS-rebinding)
// y bajo el prefijo secreto /<token>/ (anti CSRF desde otras paginas web).
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
	// Auto-elevacion: la app necesita ser administrador para limpiar/optimizar.
	if !isAdmin() {
		if elevate() {
			return
		}
		// Si el usuario cancela el UAC seguimos en modo limitado.
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("No se pudo abrir el puerto local: " + err.Error())
	}
	hostPort = ln.Addr().String()
	token = newToken()
	if len(os.Args) > 1 && os.Args[1] == "--test-token" { // solo para pruebas
		token = "test"
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
		_, _ = w.Write(indexHTML)
	}))
	mux.HandleFunc(base+"/api/ping", guard(func(w http.ResponseWriter, r *http.Request) {
		pingMu.Lock()
		lastPing = time.Now()
		pingedOnce = true
		pingMu.Unlock()
		writeJSON(w, map[string]interface{}{"ok": true, "admin": isAdmin()})
	}))
	registerAPI(mux, base)

	url := "http://" + hostPort + base + "/"
	go func() {
		time.Sleep(300 * time.Millisecond)
		openWindow(url)
	}()
	go watchdog()

	fmt.Println("Optimizador PC en", url)
	if err := http.Serve(ln, mux); err != nil {
		fatal(err.Error())
	}
}

// Cierra el programa cuando se cierra la ventana (deja de llegar el ping).
func watchdog() {
	for {
		time.Sleep(3 * time.Second)
		pingMu.Lock()
		idle := time.Since(lastPing)
		seen := pingedOnce
		pingMu.Unlock()
		if (seen && idle > 20*time.Second) || (!seen && idle > 90*time.Second) {
			os.Exit(0)
		}
	}
}

func fatal(msg string) {
	showMessage("Optimizador PC", msg)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func registerAPI(mux *http.ServeMux, base string) {
	api := func(path string, h http.HandlerFunc) { mux.HandleFunc(base+"/api/"+path, guard(h)) }

	api("diag", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, runDiagnostico()) })
	api("scan", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, scanLimpieza()) })

	api("clean", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Items []string `json:"items"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			writeErr(w, 400, "peticion invalida")
			return
		}
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) { runLimpieza(j, body.Items) })})
	})
	api("optimize", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Items []string `json:"items"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			writeErr(w, 400, "peticion invalida")
			return
		}
		writeJSON(w, map[string]string{"job": startJob(func(j *Job) { runOptimizar(j, body.Items) })})
	})
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

	api("startup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var b struct {
				Scope   string `json:"scope"`
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			}
			if json.NewDecoder(r.Body).Decode(&b) != nil {
				writeErr(w, 400, "peticion invalida")
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
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "peticion invalida")
			return
		}
		msg, err := desinstalar(b.ID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"msg": msg})
	})

	api("users", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, listUsuarios()) })
	api("makeadmin", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			User string `json:"user"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&b) != nil {
			writeErr(w, 400, "peticion invalida")
			return
		}
		msg, err := hacerAdmin(b.User)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]string{"msg": msg})
	})
}

// ---------------------------------------------------------------- Jobs

type Job struct {
	mu    sync.Mutex
	lines []string
	done  bool
}

var (
	jobs   = map[string]*Job{}
	jobsMu sync.Mutex
)

func startJob(fn func(*Job)) string {
	id := newToken()[:12]
	j := &Job{}
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

func (j *Job) log(s string) {
	j.mu.Lock()
	j.lines = append(j.lines, strings.TrimRight(s, "\r\n"))
	j.mu.Unlock()
}

func (j *Job) snapshot(from int) map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	if from < 0 || from > len(j.lines) {
		from = 0
	}
	return map[string]interface{}{"lines": j.lines[from:], "next": len(j.lines), "done": j.done}
}
