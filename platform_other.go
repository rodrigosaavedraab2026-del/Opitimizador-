//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
)

// Stubs para compilar/probar fuera de Windows. La app real es solo para Windows.

var errSoloWindows = errors.New("esta funcion solo esta disponible en Windows")

func isAdmin() bool                    { return true }
func elevate() bool                    { return false }
func showMessage(t, m string)          { fmt.Println(t+":", m) }
func openWindow(url string)            { fmt.Println("(abrir en navegador) " + url) }
func lanzarDesinstalador(string) error { return errSoloWindows }

func psOutput(script string, envv map[string]string) (string, error) { return "", errSoloWindows }

func runPS(j *Job, script string, envv map[string]string) error {
	j.log("(simulado) PowerShell")
	return errSoloWindows
}

func runNative(j *Job, exe string, args ...string) error {
	if _, err := exec.LookPath(exe); err != nil {
		j.log("(simulado) " + exe)
		return errSoloWindows
	}
	return nil
}
