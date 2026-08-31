// Package version es la única fuente de verdad de la versión del FirmadorGDI.
//
// GDI-341 — por qué hace falta. Hasta acá la versión vivía en un solo lugar:
// el atributo Version del instalador (installer/firmadorgdi.wxs). El binario
// no la exponía por ningún lado, así que no había forma de saber qué versión
// tenía instalada un municipio: ni desde la máquina del funcionario, ni desde
// un log, ni preguntando. Con un solo MSI publicado y sin auto-update, eso
// convierte cualquier reporte de error en una adivinanza.
//
// La constante de acá se imprime con --version, se escribe en el log de cada
// firma y se muestra en el diálogo informativo.
package version

// Version es la versión del binario. Se actualiza a mano junto con el
// atributo Version de installer/firmadorgdi.wxs — version_test.go verifica
// que los dos digan lo mismo, así que no pueden quedar desfasados sin que
// falle el build.
//
// Semver simple: MAJOR.MINOR.PATCH. El instalador MSI de Windows exige tres
// números y compara sus versiones campo por campo.
const Version = "1.4.0"

// Nombre del producto tal como aparece en los diálogos y en el instalador.
const Producto = "FirmadorGDI"
