package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// engancharConsola() estuvo escrita, comentada y con su variante para
// no-Windows durante dos commits que decían haber arreglado `--version`… y
// nunca se la llamó desde ningún lado. El binario se compila con -H windowsgui,
// así que sin ese enganche el Printf escribe en un handle vacío y no sale nada
// por pantalla. Se reportó como problema del shell; no lo era.
//
// El test es estático a propósito: la función solo hace algo real en Windows y
// con una consola de verdad colgando del proceso, que es justo lo que un test
// no tiene. Lo que se puede verificar acá —y es lo que falló— es que exista la
// llamada.
func TestVersionEnganchaLaConsola(t *testing.T) {
	fuente, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("no se pudo leer main.go: %v", err)
	}

	if !strings.Contains(string(fuente), "engancharConsola()") {
		t.Fatal("main.go no llama a engancharConsola(): `--version` no va a imprimir nada")
	}

	// Y tiene que llamarse ANTES del Printf, no después.
	texto := string(fuente)
	llamada := strings.Index(texto, "engancharConsola()")
	impresion := regexp.MustCompile(`fmt\.Printf\("%s %s\\n", version\.Producto`).
		FindStringIndex(texto)
	if impresion == nil {
		t.Fatal("no se encontró el Printf de --version en main.go")
	}
	if llamada > impresion[0] {
		t.Error("se engancha la consola después de imprimir: no sirve de nada")
	}
}
