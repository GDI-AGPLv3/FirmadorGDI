//go:build windows

package ui

import (
	"encoding/xml"
	"regexp"
	"strings"
	"testing"
)

// El XAML del diálogo del PIN tiene que ser XML válido. Si no lo es, PowerShell
// falla en XamlReader::Load y el funcionario se queda SIN diálogo de PIN: no
// puede firmar y el error que ve no dice nada útil.
//
// Es una trampa real de este archivo (FG-009): el XAML vive dentro de un
// here-string de PowerShell con comillas dobles, que expande variables. Un dato
// interpolado ahí con un "&" o un "<" —el label del token, el CUIL, el host del
// servidor— rompe el XML entero. Por eso el host se setea con .Text DESPUÉS del
// Load, y por eso este test existe.
var reVarPS = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)

func xamlDelDialogo(t *testing.T) string {
	t.Helper()
	script := buildPSScript()
	ini := strings.Index(script, `[xml]$xaml = @"`)
	if ini < 0 {
		t.Fatal("no se encontró el here-string del XAML: cambió la forma del script")
	}
	resto := script[ini+len(`[xml]$xaml = @"`):]
	fin := strings.Index(resto, "\n\"@")
	if fin < 0 {
		t.Fatal("no se encontró el cierre del here-string")
	}
	return resto[:fin]
}

func TestElXamlDelPinEsXMLValido(t *testing.T) {
	// Las variables de PowerShell se reemplazan por vacío: lo que se valida es
	// la estructura del XAML, no el contenido que se inyecta.
	crudo := reVarPS.ReplaceAllString(xamlDelDialogo(t), "")
	if err := xml.Unmarshal([]byte(crudo), new(interface{})); err != nil {
		t.Fatalf("el XAML del diálogo del PIN no es XML válido: %v", err)
	}
}

// El host del servidor NO puede estar interpolado en el XAML: tiene que llegar
// por .Text después del Load. Si alguien lo mete adentro del here-string, un
// host con "&" deja al funcionario sin diálogo.
func TestElServidorNoSeInterpolaEnElXaml(t *testing.T) {
	xamlCrudo := xamlDelDialogo(t)
	if strings.Contains(xamlCrudo, "$server") || strings.Contains(xamlCrudo, "AGDI_SERVER") {
		t.Error("el host del servidor está interpolado dentro del XAML: tiene que setearse con .Text después del XamlReader (FG-009)")
	}

	script := buildPSScript()
	if !strings.Contains(script, `$txtServer = $win.FindName('txtServer')`) {
		t.Error("el script no busca el TextBlock del servidor por FindName")
	}
	if !strings.Contains(script, "$txtServer.Text = $env:AGDI_SERVER") {
		t.Error("el script no setea el host del servidor por .Text")
	}
}

// El diálogo tiene que nombrar al servidor SIEMPRE, también cuando el link no
// lo trae: un lugar vacío se lee como "no hay nada raro".
func TestSinServidorElDialogoLoDiceIgual(t *testing.T) {
	script := buildPSScript()
	if !strings.Contains(script, "(el link no dice a que servidor)") {
		t.Error("falta el texto para cuando AGDI_SERVER viene vacío")
	}
}

// El cartel tiene que estar en el diálogo del PIN, no en otro lado: es el único
// momento en el que el funcionario puede frenar.
func TestElCartelDelServidorEstaEnElDialogoDelPin(t *testing.T) {
	x := xamlDelDialogo(t)
	for _, frag := range []string{"LAS FIRMAS VAN A ESTE SERVIDOR", `x:Name="txtServer"`, "no pongas el PIN"} {
		if !strings.Contains(x, frag) {
			t.Errorf("falta %q en el XAML del diálogo del PIN", frag)
		}
	}
}
