package hostsconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// El instalador tiene que escribir la lista donde SOLO un administrador puede
// cambiarla. Si alguien la mueve a HKCU o a un archivo junto al .exe, la
// escribe el propio usuario — y entonces cualquier cosa que corra como el
// funcionario se autoriza sola, que es exactamente FG-001 con pasos extra.
//
// Este test lee el .wxs como texto: no hace falta Windows para comprobarlo.
func wxs(t *testing.T) string {
	t.Helper()
	ruta := filepath.Join("..", "..", "installer", "firmadorgdi.wxs")
	b, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}
	return string(b)
}

func TestElInstaladorEscribeLosHostsEnHKLM(t *testing.T) {
	s := wxs(t)

	if !strings.Contains(s, `Root="HKLM" Key="SOFTWARE\GDILatam\FirmadorGDI"`) {
		t.Error("el instalador no escribe SOFTWARE\\GDILatam\\FirmadorGDI en HKLM")
	}
	if !strings.Contains(s, `Name="`+NombreValor+`"`) {
		t.Errorf("el instalador no escribe el valor %q que lee Leer()", NombreValor)
	}
	if !strings.Contains(s, `Value="[SERVIDORGDI]"`) {
		t.Error("el valor no sale de la propiedad SERVIDORGDI")
	}
}

// La propiedad tiene que ser Secure="yes" o el valor se pierde al pasar a la
// parte elevada de la instalación: la clave queda vacía y el municipio no puede
// firmar, sin ningún error visible.
func TestLaPropiedadDelServidorEsSecure(t *testing.T) {
	s := wxs(t)
	if !strings.Contains(s, `<Property Id="SERVIDORGDI" Secure="yes"`) {
		t.Error("SERVIDORGDI tiene que declararse con Secure=\"yes\"")
	}
}

// Una instalación SaaS no pasa servidor: el componente no se instala y no queda
// una clave creada y vacía dando vueltas.
func TestSinServidorNoSeEscribeNada(t *testing.T) {
	s := wxs(t)
	if !strings.Contains(s, `Condition="SERVIDORGDI"`) {
		t.Error("el componente del servidor no tiene Condition: se instalaría siempre, también en SaaS")
	}
}

// El valor del registro y la ruta documentada tienen que ser los mismos que lee
// el código. Si alguien cambia uno y no el otro, el municipio no puede firmar y
// el log apunta al lugar equivocado.
func TestLaRutaDocumentadaCoincideConElInstalador(t *testing.T) {
	if !strings.HasPrefix(RutaRegistro, `HKLM\`) {
		t.Errorf("RutaRegistro debería empezar en HKLM y dice %q", RutaRegistro)
	}
	s := wxs(t)
	clave := strings.TrimPrefix(RutaRegistro, `HKLM\`)
	if !strings.Contains(s, clave) {
		t.Errorf("el instalador no usa la clave documentada %q", clave)
	}
}

func TestLimpiarDescartaVaciosYEspacios(t *testing.T) {
	got := limpiar([]string{"  api.muni.gob.ar ", "", "   ", "otro.muni.gob.ar"})
	if len(got) != 2 || got[0] != "api.muni.gob.ar" || got[1] != "otro.muni.gob.ar" {
		t.Errorf("limpiar() = %v", got)
	}
}
