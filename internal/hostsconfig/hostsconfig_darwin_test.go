//go:build darwin

package hostsconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// Un archivo con el contenido correcto pero que NO es de root se ignora. Es el
// caso que importa: el que escribiría algo que corre como el funcionario para
// autorizarse solo. Los tests no corren como root, así que el archivo que se
// crea acá es justo eso — del usuario — y tiene que quedar afuera.
func TestUnArchivoQueNoEsDeRootSeIgnora(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("corriendo como root: el archivo de prueba sería de root y valdría")
	}
	ruta := filepath.Join(t.TempDir(), NombreValor)
	if err := os.WriteFile(ruta, []byte("servidor-ajeno.ejemplo.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := leerArchivo(ruta); len(got) != 0 {
		t.Errorf("se aceptaron hosts de un archivo del propio usuario: %v", got)
	}
}

func TestSinArchivoNoHayHostsDeInstalacion(t *testing.T) {
	if got := leerArchivo(filepath.Join(t.TempDir(), "no-existe")); len(got) != 0 {
		t.Errorf("sin archivo se esperaba vacío y vino %v", got)
	}
}
