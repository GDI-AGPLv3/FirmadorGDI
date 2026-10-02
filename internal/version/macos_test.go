package version

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdi-latam/firmadorgdi/internal/uri"
)

// Los archivos del instalador de macOS se leen como texto: el .pkg solo se
// puede armar en una Mac, pero que estos archivos digan lo que tienen que decir
// se comprueba en cualquier máquina — igual que con el .wxs.
func archivoMac(t *testing.T, nombre ...string) string {
	t.Helper()
	ruta := filepath.Join(append([]string{"..", "..", "installer", "macos"}, nombre...)...)
	b, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}
	return string(b)
}

// Un XML roto acá no se nota hasta que alguien arma el .pkg. Mismo motivo que
// TestElInstaladorEsXMLValido para el MSI.
func TestLosArchivosDelInstaladorDeMacSonXMLValido(t *testing.T) {
	for _, nombre := range []string{"Info.plist", "entitlements.plist", "distribution.xml"} {
		var v any
		if err := xml.Unmarshal([]byte(archivoMac(t, nombre)), &v); err != nil {
			t.Errorf("%s no es XML válido — el .pkg no va a armarse: %v", nombre, err)
		}
	}
}

// En el MSI la versión está escrita dos veces y un test las compara. En macOS
// directamente no se escribe: el Info.plist y el guion del instalador llevan
// __VERSION__ y build.sh lo reemplaza con la constante de version.go. Si
// alguien pone un número a mano, vuelve la deriva que GDI-341 vino a cerrar.
func TestElInstaladorDeMacTomaLaVersionDeVersionGo(t *testing.T) {
	plist := archivoMac(t, "Info.plist")
	for _, clave := range []string{"CFBundleShortVersionString", "CFBundleVersion"} {
		if !strings.Contains(plist, "<key>"+clave+"</key>\n\t<string>__VERSION__</string>") {
			t.Errorf("Info.plist: %s tiene que ser __VERSION__, no un número a mano", clave)
		}
	}
	if !strings.Contains(archivoMac(t, "distribution.xml"), `version="__VERSION__"`) {
		t.Error("distribution.xml: la versión del paquete tiene que ser __VERSION__")
	}

	build := archivoMac(t, "build.sh")
	if !strings.Contains(build, "internal/version/version.go") {
		t.Error("build.sh no lee la versión de internal/version/version.go")
	}
	if !strings.Contains(build, `s/__VERSION__/$VERSION/g`) {
		t.Error("build.sh no reemplaza __VERSION__")
	}
}

// El scheme que declara el .app tiene que ser el que parsea el programa. Si se
// separan, el navegador abre FirmadorGDI con un link que el programa rechaza —
// o no lo abre nunca.
func TestElAppDeMacAtiendeElMismoSchemeQueElPrograma(t *testing.T) {
	plist := archivoMac(t, "Info.plist")
	if !strings.Contains(plist, "<key>CFBundleURLSchemes</key>") {
		t.Fatal("Info.plist no declara CFBundleURLSchemes: macOS no sabría quién atiende el link")
	}
	if !strings.Contains(plist, "<string>"+uri.Scheme+"</string>") {
		t.Errorf("Info.plist no declara el scheme %q", uri.Scheme)
	}
}

// Por defecto pkgbuild marca el .app como "reubicable": si en la Mac ya hay
// otra copia de FirmadorGDI.app en cualquier carpeta, el instalador actualiza
// ESA y no pone nada en /Applications. Queda "instalado" y sin instalar.
func TestElPaqueteDeMacNoEsReubicable(t *testing.T) {
	if !strings.Contains(archivoMac(t, "build.sh"), `"Set :0:BundleIsRelocatable false"`) {
		t.Error("build.sh no apaga BundleIsRelocatable: el .pkg puede instalar fuera de /Applications")
	}
}

// Firmado con Developer ID el programa corre con "hardened runtime", que no
// deja cargar librerías de otro firmante. El driver PKCS#11 del token ES de
// otro firmante: sin este permiso el firmador queda notarizado y sin poder
// abrir ningún token.
func TestElAppFirmadoDeMacPuedeCargarElDriverDelToken(t *testing.T) {
	if !strings.Contains(archivoMac(t, "entitlements.plist"),
		"<key>com.apple.security.cs.disable-library-validation</key>\n\t<true/>") {
		t.Error("entitlements.plist no declara disable-library-validation")
	}
	if !strings.Contains(archivoMac(t, "build.sh"), `--entitlements "$MAC/entitlements.plist"`) {
		t.Error("build.sh no firma con entitlements.plist")
	}
}

// Los scripts del instalador corren en macOS: con fin de línea de Windows el
// shebang queda "#!/bin/sh\r" y el sistema no encuentra el intérprete.
func TestLosScriptsDeMacNoSeConviertenACRLF(t *testing.T) {
	atributos, err := os.ReadFile(filepath.Join("..", "..", ".gitattributes"))
	if err != nil {
		t.Fatalf("no se pudo leer .gitattributes: %v", err)
	}
	for _, regla := range []string{"*.sh text eol=lf", "installer/macos/scripts/* text eol=lf"} {
		if !strings.Contains(string(atributos), regla) {
			t.Errorf(".gitattributes no fija %q", regla)
		}
	}
}

// Go linkea TODO archivo .syso que encuentra en la carpeta del paquete, en
// cualquier sistema, salvo que el nombre termine en _<sistema>. El ícono del
// .exe es un recurso de Windows: sin el sufijo, en macOS el linker lo recibe,
// no lo entiende ("unknown file type") y el programa no compila. Pasó con la
// primera corrida del workflow de macOS: el archivo se llamaba firmadorgdi.syso.
func TestLosRecursosDeWindowsNoSeLinkeanEnOtrosSistemas(t *testing.T) {
	recursos, err := filepath.Glob(filepath.Join("..", "..", "cmd", "firmadorgdi", "*.syso"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recursos) == 0 {
		t.Fatal("no se encontró el .syso con el ícono del .exe: el test quedó mirando otra carpeta")
	}
	for _, r := range recursos {
		nombre := strings.TrimSuffix(filepath.Base(r), ".syso")
		if !strings.HasSuffix(nombre, "_windows") && !strings.Contains(nombre, "_windows_") {
			t.Errorf("%s no dice _windows en el nombre: se linkea también en macOS y rompe el build", filepath.Base(r))
		}
	}
}
