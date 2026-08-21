//go:build !windows

package main

// En las plataformas que no son Windows el binario no se compila con
// `-H windowsgui`, asi que la salida estandar funciona sola.
func engancharConsola() {}
