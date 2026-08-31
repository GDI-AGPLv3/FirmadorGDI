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

// GDI-405 — el PIN va PRIMERO, antes de hablar con el servidor.
//
// Es el orden lo que hace al cambio: hasta 1.3.1 se bajaba el PDF entero y
// recién después se abría el token, así que una cancelación en el PIN tiraba a
// la basura una descarga de hasta 50 MB. Y ahora hay una razón más dura: el
// servidor no puede preparar nada sin el certificado, y el certificado sale del
// token. Si alguien vuelve a poner una llamada de red antes del login, el
// circuito nuevo deja de tener sentido y nadie se entera hasta producción.
//
// El test es estático porque el flujo real necesita un token físico.
func TestElPINVaAntesDeHablarConElServidor(t *testing.T) {
	fuente, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("no se pudo leer main.go: %v", err)
	}

	cuerpo := funcionHandleSign(t, string(fuente))

	login := strings.Index(cuerpo, "pedirPINYLoguear")
	if login < 0 {
		t.Fatal("handleSign no pide el PIN")
	}
	for _, llamadaDeRed := range []string{
		"storage.FetchEnvelope", "storage.PostCert", "storage.EsperarDigests",
	} {
		pos := strings.Index(cuerpo, llamadaDeRed)
		if pos < 0 {
			t.Errorf("handleSign ya no llama a %s", llamadaDeRed)
			continue
		}
		if pos < login {
			t.Errorf("%s ocurre ANTES del PIN: el token tiene que abrirse primero", llamadaDeRed)
		}
	}
}

// funcionHandleSign devuelve el cuerpo de handleSign, hasta la función
// siguiente. Sin esto el test mediría posiciones de todo el archivo y los
// helpers de más abajo lo ensuciarían.
func funcionHandleSign(t *testing.T, fuente string) string {
	t.Helper()

	inicio := strings.Index(fuente, "func handleSign(")
	if inicio < 0 {
		t.Fatal("no se encontró handleSign en main.go")
	}
	resto := fuente[inicio+1:]
	if fin := strings.Index(resto, "\nfunc "); fin >= 0 {
		return resto[:fin]
	}
	return resto
}
