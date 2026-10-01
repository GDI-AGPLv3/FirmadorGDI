package ui

import (
	"strconv"
	"strings"
)

// textoDelPIN arma lo que dice el diálogo del PIN en macOS: el título y el
// bloque de texto de abajo. En Windows ese texto vive dentro del XAML.
//
// Está en un archivo SIN build tag —aunque solo lo usa dialog_darwin.go— para
// que sus tests corran en cualquier máquina: lo que se le dice al funcionario
// antes de que ponga el PIN (a qué servidor van las firmas, cuántos documentos
// firma) es la parte del diálogo que no puede romperse en silencio, y una Mac
// para probarlo a mano no siempre hay.
func textoDelPIN(info TokenInfo) (titulo, detalle string) {
	titulo = "FirmadorGDI — Firma digital con token físico"

	var b strings.Builder
	if info.WrongPIN {
		b.WriteString("PIN INCORRECTO. Intentá de nuevo.\n\n")
	}

	b.WriteString("TOKEN DETECTADO\n")
	b.WriteString(sanitize(info.Label))
	if m := sanitize(info.Manufacturer); m != "" {
		b.WriteString("  ·  " + m)
	}
	b.WriteString("\nCUIL: " + sanitize(info.SerialNumber))
	if v := sanitize(info.ValidUntil); v != "" {
		b.WriteString("\nVálido hasta " + v)
	}

	// GDI-167: con una tanda, el diálogo dice CUÁNTOS documentos se firman con
	// este PIN. Sin eso el funcionario estaría autorizando a ciegas.
	if info.BatchCount > 1 {
		b.WriteString("\n\nFIRMA EN TANDA\n")
		b.WriteString("Vas a firmar " + strconv.Itoa(info.BatchCount) + " documentos\n")
		b.WriteString("Con un solo PIN. Si alguno falla, no queda ninguno firmado.")
	}

	// El servidor va SIEMPRE, también cuando el link no lo trae: un lugar vacío
	// se lee como "no hay nada raro".
	servidor := sanitize(info.Servidor)
	if servidor == "" {
		servidor = "(el link no dice a qué servidor)"
	}
	b.WriteString("\n\nLAS FIRMAS VAN A ESTE SERVIDOR\n")
	b.WriteString(servidor)
	b.WriteString("\nSi no lo reconocés, no pongas el PIN: cancelá y avisá a sistemas.")

	return titulo, b.String()
}

// sanitize elimina bytes NUL y recorta espacios — los strings PKCS#11 son C fijos.
func sanitize(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\x00", ""), " ")
}
