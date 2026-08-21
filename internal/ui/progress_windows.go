//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

// tituloDeVentana escribe el avance en el título de la consola.
//
// Es lo más barato que informa de verdad: no abre una ventana nueva, no bloquea
// y no puede fallar de una forma que arruine la firma. Una tanda son 5
// documentos, no 500 — una barra animada acá sería más código y más superficie
// para romper, a cambio de nada.
func tituloDeVentana(actual, total int) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setTitle := kernel32.NewProc("SetConsoleTitleW")

	texto := "FirmadorGDI — firmando " + itoa(actual) + " de " + itoa(total) + "…"
	ptr, err := syscall.UTF16PtrFromString(texto)
	if err != nil {
		return
	}
	//nolint:errcheck // informar el progreso nunca puede romper la firma
	_, _, _ = setTitle.Call(uintptr(unsafe.Pointer(ptr)))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
