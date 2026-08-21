package version

import (
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

func TestLaVersionEsSemver(t *testing.T) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(Version) {
		t.Errorf("versión %q: el MSI de Windows exige MAJOR.MINOR.PATCH", Version)
	}
}
