package version

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// El MSI y el binario tienen que decir la misma versión. Son dos archivos
// distintos que se editan a mano, así que la deriva es cuestión de tiempo: sin
// este test, alguien sube la versión del instalador, publica, y el binario
// sigue reportando la vieja — que es exactamente el problema que GDI-341 vino
// a resolver.
func TestLaVersionCoincideConLaDelInstalador(t *testing.T) {
	ruta := filepath.Join("..", "..", "installer", "firmadorgdi.wxs")
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}

	re := regexp.MustCompile(`Version="([0-9]+\.[0-9]+\.[0-9]+)"`)
	m := re.FindSubmatch(contenido)
	if m == nil {
		t.Fatal("no se encontró el atributo Version en firmadorgdi.wxs")
	}

	if string(m[1]) != Version {
		t.Errorf(
			"el instalador dice %s y el binario %s — se actualizan JUNTOS",
			m[1], Version,
		)
	}
}

// El .wxs se edita a mano y un XML roto NO se nota hasta que alguien compila el
// MSI — que es un paso manual y que puede pasar semanas después. Pasó: un
// comentario metido entre los atributos de <Package> dejó el instalador sin
// compilar, y el test de versión de arriba seguía verde porque lee con regex.
func TestElInstaladorEsXMLValido(t *testing.T) {
	ruta := filepath.Join("..", "..", "installer", "firmadorgdi.wxs")
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}

	var v any
	if err := xml.Unmarshal(contenido, &v); err != nil {
		t.Fatalf("firmadorgdi.wxs no es XML válido — el MSI no va a compilar: %v", err)
	}
}

// El MSI se publica copiando UN archivo a R2. Si WiX deja los archivos en un
// .cab externo, lo publicado NO INSTALA: al ejecutarlo pide "Source file not
// found: cab1.cab". Pasó al compilar 1.2.0 — el .wxs nunca había declarado
// dónde iban los archivos, así que el instalador que se venía publicando tiene
// el mismo problema.
func TestElInstaladorEmbebeSusArchivos(t *testing.T) {
	ruta := filepath.Join("..", "..", "installer", "firmadorgdi.wxs")
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("no se pudo leer %s: %v", ruta, err)
	}

	if !regexp.MustCompile(`EmbedCab\s*=\s*"yes"`).Match(contenido) {
		t.Error(
			"firmadorgdi.wxs no declara MediaTemplate EmbedCab=\"yes\": el MSI va " +
				"a salir con un .cab al lado y, publicado solo, no instala nada",
		)
	}
}

func TestLaVersionEsSemver(t *testing.T) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(Version) {
		t.Errorf("versión %q: el MSI de Windows exige MAJOR.MINOR.PATCH", Version)
	}
}
