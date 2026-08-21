//go:build !windows

package ui

// En las plataformas que todavía no tienen UI nativa (ver dialog_darwin.go), el
// avance queda solo en el log. No es una limitación de la tanda: el firmador
// entero es Windows-first.
func tituloDeVentana(actual, total int) {}
