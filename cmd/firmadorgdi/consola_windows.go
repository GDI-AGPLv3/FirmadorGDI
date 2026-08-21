//go:build windows

package main

import (
	"os"
	"syscall"
)

// engancharConsola intenta darle al programa un lugar donde escribir.
//
// El binario se compila con `-H windowsgui`: sin eso, Chrome abriría una ventana
// negra en CADA firma, que es el caso normal y sería horrible. El costo es que
// Windows no le da consola al proceso, así que un `fmt.Printf` no se ve.
//
// Devuelve true si quedó una salida utilizable.
//
// ⚠️ Si ya HAY una salida válida —o sea, alguien redirigió a un archivo o a una
// tubería— no se toca nada. Una primera versión de esto enganchaba la consola
// siempre y pisaba `os.Stdout`, con lo cual `--version > version.txt` dejaba el
// archivo vacío: se rompía justamente el uso que más importa, el del script de
// soporte que quiere capturar la versión.
func engancharConsola() bool {
	// ¿Ya hay dónde escribir? Con -H windowsgui y sin redirección, Stat() falla.
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		return true // archivo o tubería: respetarlo
	}

	const attachParentProcess = ^uintptr(0) // (DWORD)-1

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")

	if ok, _, _ := attach.Call(attachParentProcess); ok == 0 {
		return false // nos abrieron con doble clic: no hay consola de nadie
	}

	salida, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	os.Stdout = salida
	os.Stderr = salida
	return true
}
