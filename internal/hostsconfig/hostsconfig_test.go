package hostsconfig

import (
	"io/fs"
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

// ── macOS ───────────────────────────────────────────────────────────────────

// En macOS no hay HKLM: lo que hace segura a la lista es que el archivo —y la
// carpeta donde está— sean de root y no los pueda escribir nadie más. Si esta
// función afloja, cualquier cosa que corra como el funcionario se autoriza
// sola: FG-001 con pasos extra, igual que un valor en HKCU.
func TestEnMacSoloValeLoQueEscribeRoot(t *testing.T) {
	casos := []struct {
		nombre string
		uid    uint32
		modo   fs.FileMode
		vale   bool
	}{
		{"archivo de root 644", 0, 0o644, true},
		{"carpeta de root 755", 0, fs.ModeDir | 0o755, true},
		{"del propio usuario", 501, 0o644, false},
		{"de root pero lo escribe el grupo", 0, 0o664, false},
		{"de root pero lo escribe cualquiera", 0, 0o646, false},
		{"carpeta de root abierta a todos", 0, fs.ModeDir | 0o777, false},
		// Con 755 a propósito: con 777 lo rechazarían los permisos y el caso
		// no probaría que un enlace se rechaza POR SER enlace.
		{"enlace simbólico de root", 0, fs.ModeSymlink | 0o755, false},
	}
	for _, c := range casos {
		err := soloLoEscribeRoot(c.uid, c.modo)
		if c.vale && err != nil {
			t.Errorf("%s: tendría que valer y se rechaza: %v", c.nombre, err)
		}
		if !c.vale && err == nil {
			t.Errorf("%s: se ACEPTA y no tendría que valer", c.nombre)
		}
	}
}

func TestElArchivoDeMacSeLeeLineaPorLinea(t *testing.T) {
	got := limpiar(hostsDeTexto("# servidor del municipio\napi.muni.gob.ar\r\n\n  otro.muni.gob.ar ; tercero.muni.gob.ar\n"))
	want := []string{"api.muni.gob.ar", "otro.muni.gob.ar", "tercero.muni.gob.ar"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("hostsDeTexto() = %v, se esperaba %v", got, want)
	}
}

// La última pantalla del instalador de macOS le dice al administrador dónde
// escribir el servidor. Si esa ruta y la que lee Leer() se separan, el
// municipio sigue las instrucciones al pie de la letra y no puede firmar.
func TestElInstaladorDeMacDocumentaLaRutaQueSeLee(t *testing.T) {
	ruta := filepath.Join("..", "..", "installer", "macos", "recursos", "listo.html")
	b, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}
	if !strings.Contains(string(b), `sudo tee "`+RutaArchivoMac+`"`) {
		t.Errorf("listo.html no manda a escribir %q con sudo", RutaArchivoMac)
	}
	if !strings.HasPrefix(RutaArchivoMac, "/Library/") {
		t.Errorf("RutaArchivoMac tiene que estar bajo /Library (de root) y dice %q", RutaArchivoMac)
	}
}

// ── Windows: las dos vistas del registro (GDI-804A) ────────────────────────

func vistaFija(nombre string, hosts []string, ok bool) vista {
	return vista{nombre, func() ([]string, bool) { return hosts, ok }}
}

// El MSI es de 32 bits: en un Windows de 64 el valor queda en WOW6432Node, la
// vista de 32. Con la de 64 vacía, lo de la de 32 TIENE que llegar. Es el caso
// que se vio en la PC A el 30/10 con la 1.8.0.
func TestSiSoloEstaEnLaVistaDe32SeLee(t *testing.T) {
	got := unirVistas(
		vistaFija("64", nil, false),
		vistaFija("32", []string{"enlace-dev.gdi.lat"}, true),
	)
	if strings.Join(got, "|") != "enlace-dev.gdi.lat" {
		t.Errorf("unirVistas() = %v, se esperaba el host de la vista de 32", got)
	}
}

func TestSiSoloEstaEnLaVistaDe64SeLee(t *testing.T) {
	got := unirVistas(
		vistaFija("64", []string{"api.muni.gob.ar"}, true),
		vistaFija("32", nil, false),
	)
	if strings.Join(got, "|") != "api.muni.gob.ar" {
		t.Errorf("unirVistas() = %v", got)
	}
}

// Si hay valor en las dos (el MSI en una, un administrador a mano en la otra)
// se suman, primero la de 64, y un host repetido cuenta una vez.
func TestConValorEnLasDosVistasSeSumanSinRepetir(t *testing.T) {
	got := unirVistas(
		vistaFija("64", []string{"api.muni.gob.ar", " otro.muni.gob.ar "}, true),
		vistaFija("32", []string{"otro.muni.gob.ar", "", "tercero.muni.gob.ar"}, true),
	)
	want := []string{"api.muni.gob.ar", "otro.muni.gob.ar", "tercero.muni.gob.ar"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("unirVistas() = %v, se esperaba %v", got, want)
	}
}

func TestSinValorEnNingunaVistaNoHayHosts(t *testing.T) {
	if got := unirVistas(vistaFija("64", nil, false), vistaFija("32", nil, false)); len(got) != 0 {
		t.Errorf("sin valor en ninguna vista se esperaba vacío y vino %v", got)
	}
}

// unirVistas NO valida: lo que trae pasa igual por uri.AgregarHostsAutorizados,
// que rechaza sufijos y comodines. Este test fija que no se "arregle" nada acá
// en silencio (un sufijo sigue llegando tal cual a la validación, que lo tira).
func TestUnirVistasNoTocaLoQueValidaURI(t *testing.T) {
	got := unirVistas(vistaFija("32", []string{".fly.dev", "*.muni.gob.ar"}, true))
	if strings.Join(got, "|") != ".fly.dev|*.muni.gob.ar" {
		t.Errorf("unirVistas() = %v", got)
	}
}

// Leer() en Windows tiene que pedir las DOS vistas. Si alguien saca la de 32,
// los municipios con el MSI de 32 bits vuelven a quedar sin poder firmar.
func TestEnWindowsSeLeenLasDosVistas(t *testing.T) {
	b, err := os.ReadFile("hostsconfig_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, flag := range []string{"registry.WOW64_64KEY", "registry.WOW64_32KEY"} {
		if !strings.Contains(s, flag) {
			t.Errorf("hostsconfig_windows.go no lee la vista %s", flag)
		}
	}
	if !strings.Contains(s, "registry.LOCAL_MACHINE") || strings.Contains(s, "registry.CURRENT_USER") {
		t.Error("la lista se lee solo de HKLM: HKCU la escribe el propio usuario (FG-001)")
	}
}
