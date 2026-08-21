//go:build windows

package main

import (
	"os"
	"syscall"
)

// engancharConsola conecta la salida del programa a la consola desde la que lo
// llamaron, si es que lo llamaron desde una.
//
// Hace falta porque el binario se compila con `-H windowsgui`: eso evita que se
// abra una ventana negra cada vez que Chrome lanza el firmador para firmar
// —que es el caso normal y sería horrible—, pero tiene un costo: Windows NO le
// da consola al proceso, así que un `fmt.Printf` no se ve en ningún lado.
//
// Resultado: `firmadorgdi.exe --version` se ejecutaba, salía bien… y no
// imprimía nada. La versión, que es justamente lo que GDI-341 vino a poder
// consultar, seguía sin poder consultarse.
//
// ATTACH_PARENT_PROCESS le pide a Windows la consola del proceso que lo lanzó.
// Si no hay ninguna (Chrome, el Explorador, un doble clic), falla en silencio y
// el programa sigue igual que siempre: esto solo agrega salida cuando hay dónde
// escribirla.
func engancharConsola() {
	const attachParentProcess = ^uintptr(0) // (DWORD)-1

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")

	ok, _, _ := attach.Call(attachParentProcess)
	if ok == 0 {
		return // no nos llamaron desde una consola: no hay nada que hacer
	}

	// Reabrir los descriptores estándar apuntando a la consola recién
	// enganchada. Sin esto, el runtime de Go sigue escribiendo a los handles
	// vacíos con los que arrancó.
	if salida, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = salida
		os.Stderr = salida
	}
}
