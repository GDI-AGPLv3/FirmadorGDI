//go:build !windows

package ui

// Fuera de Windows el avance de la tanda queda solo en el log. En macOS los
// diálogos son nativos (dialog_darwin.go) pero no hay una ventana a la que
// cambiarle el título mientras se firma: una tanda son 5 documentos y termina
// antes de que haga falta.
func tituloDeVentana(actual, total int) {}
