package ui

import (
	"os"
	"strings"
	"testing"
)

func infoDePrueba() TokenInfo {
	return TokenInfo{
		Label:        "PEREZ, Juan",
		Manufacturer: "EnterSafe",
		SerialNumber: "CUIL 20123456789",
		ValidUntil:   "31/12/2030",
		Servidor:     "enlace-arg.gdilatam.com",
	}
}

// El cartel del servidor es la defensa que no depende de la lista de hosts
// (1.5.0): el funcionario tiene que ver a dónde van las firmas ANTES del PIN.
// En Windows lo exigen los tests del XAML; este es el mismo requisito para el
// diálogo de macOS.
func TestElDialogoDeMacDiceElServidor(t *testing.T) {
	_, detalle := textoDelPIN(infoDePrueba())
	for _, frag := range []string{
		"LAS FIRMAS VAN A ESTE SERVIDOR", "enlace-arg.gdilatam.com", "no pongas el PIN",
	} {
		if !strings.Contains(detalle, frag) {
			t.Errorf("falta %q en el diálogo del PIN de macOS:\n%s", frag, detalle)
		}
	}
}

func TestSinServidorElDialogoDeMacLoDiceIgual(t *testing.T) {
	info := infoDePrueba()
	info.Servidor = ""
	_, detalle := textoDelPIN(info)
	if !strings.Contains(detalle, "(el link no dice a qué servidor)") {
		t.Errorf("sin servidor el diálogo tiene que decirlo, y dice:\n%s", detalle)
	}
}

// GDI-167, condición D1-bis: autorizar una tanda sin saber cuántos documentos
// incluye no es autorizar nada.
func TestLaTandaDiceCuantosDocumentosEnMac(t *testing.T) {
	info := infoDePrueba()
	info.BatchCount = 5
	_, detalle := textoDelPIN(info)
	if !strings.Contains(detalle, "Vas a firmar 5 documentos") {
		t.Errorf("la tanda no dice cuántos documentos se firman:\n%s", detalle)
	}

	info.BatchCount = 1
	if _, detalle := textoDelPIN(info); strings.Contains(detalle, "TANDA") {
		t.Errorf("una firma sola no es una tanda:\n%s", detalle)
	}
}

func TestElPinIncorrectoSeAvisaEnMac(t *testing.T) {
	_, detalle := textoDelPIN(infoDePrueba().WithWrongPIN())
	if !strings.HasPrefix(detalle, "PIN INCORRECTO") {
		t.Errorf("el aviso de PIN incorrecto tiene que ser lo primero que se lee:\n%s", detalle)
	}
	if _, detalle := textoDelPIN(infoDePrueba()); strings.Contains(detalle, "INCORRECTO") {
		t.Error("el primer intento no puede decir que el PIN es incorrecto")
	}
}

// Los strings de PKCS#11 vienen rellenos con espacios y a veces con NUL. Un NUL
// en el medio CORTA el texto al pasarlo a C: todo lo que viene después —el
// cartel del servidor incluido— desaparecería del diálogo sin ningún error.
func TestUnNulDelTokenNoCortaElDialogoDeMac(t *testing.T) {
	info := infoDePrueba()
	info.Label = "PEREZ, Juan\x00\x00      "
	info.Manufacturer = "EnterSafe\x00"
	_, detalle := textoDelPIN(info)
	if strings.Contains(detalle, "\x00") {
		t.Fatal("quedó un NUL en el texto: C lo toma como fin del string")
	}
	if !strings.Contains(detalle, "enlace-arg.gdilatam.com") {
		t.Error("el cartel del servidor se perdió")
	}
}

// El borrador de macOS mostraba los diálogos con osascript, interpolando el
// label del token dentro del script: una comilla ahí se ejecutaba como
// AppleScript. Los textos tienen que viajar como datos. Es un test estático
// —como los del XAML— porque el archivo solo compila en una Mac.
func TestElDialogoDeMacNoArmaScriptsConDatos(t *testing.T) {
	fuente, err := os.ReadFile("dialog_darwin.go")
	if err != nil {
		t.Fatalf("no se pudo leer dialog_darwin.go: %v", err)
	}
	codigo := sinComentarios(string(fuente))
	for _, prohibido := range []string{"osascript", "exec.Command", "stringWithFormat"} {
		if strings.Contains(codigo, prohibido) {
			t.Errorf("dialog_darwin.go usa %q: los textos del diálogo no pueden pasar por un script ni por un formato", prohibido)
		}
	}
	if !strings.Contains(codigo, "textoDelPIN(info)") {
		t.Error("ShowPINDialog no arma el texto con textoDelPIN: los tests de arriba no estarían probando lo que se muestra")
	}
}

// sinComentarios saca las líneas de comentario: los comentarios de
// dialog_darwin.go nombran osascript para explicar por qué no se usa.
func sinComentarios(fuente string) string {
	var b strings.Builder
	for _, linea := range strings.Split(fuente, "\n") {
		if strings.HasPrefix(strings.TrimSpace(linea), "//") {
			continue
		}
		b.WriteString(linea)
		b.WriteString("\n")
	}
	return b.String()
}
