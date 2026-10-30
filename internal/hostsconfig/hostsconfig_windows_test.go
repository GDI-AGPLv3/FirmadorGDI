//go:build windows

package hostsconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// leerVista contra el registro de verdad. Se usa una clave temporal en HKCU
// solo porque los tests no corren como administrador: el código de producción
// lee únicamente HKLM (ver TestEnWindowsSeLeenLasDosVistas).
func claveDePrueba(t *testing.T) string {
	t.Helper()
	ruta := fmt.Sprintf(`Software\GDILatam-test\FirmadorGDI-%d`, os.Getpid())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, ruta, registry.SET_VALUE)
	if err != nil {
		t.Skipf("no se pudo crear la clave de prueba: %v", err)
	}
	k.Close()
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, ruta)
		registry.DeleteKey(registry.CURRENT_USER, `Software\GDILatam-test`)
	})
	return ruta
}

func TestLeerVistaREG_SZ(t *testing.T) {
	ruta := claveDePrueba(t)
	k, _ := registry.OpenKey(registry.CURRENT_USER, ruta, registry.SET_VALUE)
	k.SetStringValue(NombreValor, "api.muni.gob.ar;otro.muni.gob.ar")
	k.Close()

	for _, v := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		got, ok := leerVista(registry.CURRENT_USER, ruta, v)
		if !ok || strings.Join(got, "|") != "api.muni.gob.ar|otro.muni.gob.ar" {
			t.Errorf("vista %#x: leerVista() = %v, %v", v, got, ok)
		}
	}
}

func TestLeerVistaREG_MULTI_SZ(t *testing.T) {
	ruta := claveDePrueba(t)
	k, _ := registry.OpenKey(registry.CURRENT_USER, ruta, registry.SET_VALUE)
	k.SetStringsValue(NombreValor, []string{"api.muni.gob.ar", "otro.muni.gob.ar"})
	k.Close()

	got, ok := leerVista(registry.CURRENT_USER, ruta, registry.WOW64_32KEY)
	if !ok || strings.Join(got, "|") != "api.muni.gob.ar|otro.muni.gob.ar" {
		t.Errorf("leerVista() = %v, %v", got, ok)
	}
}

// Clave sin el valor, o clave que no existe: false, para que se pruebe la
// otra vista.
func TestLeerVistaSinValorOSinClave(t *testing.T) {
	ruta := claveDePrueba(t)
	if got, ok := leerVista(registry.CURRENT_USER, ruta, registry.WOW64_64KEY); ok {
		t.Errorf("clave sin valor: se esperaba false y vino %v", got)
	}
	if got, ok := leerVista(registry.CURRENT_USER, ruta+`\no-existe`, registry.WOW64_32KEY); ok {
		t.Errorf("clave inexistente: se esperaba false y vino %v", got)
	}
}
