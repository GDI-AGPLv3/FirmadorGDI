//go:build windows

package hostsconfig

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

const origen = RutaRegistro + `\` + NombreValor

// claveRegistro es RutaRegistro sin el "HKLM\": lo que recibe OpenKey.
const claveRegistro = `SOFTWARE\GDILatam\FirmadorGDI`

// Leer devuelve los hosts que el administrador autorizó al instalar.
//
// Soft-fail a propósito: si la clave no existe —que es el caso NORMAL de una
// instalación SaaS— devuelve vacío y el programa sigue con los hosts
// compilados. Un error leyendo el registro nunca puede impedir firmar.
//
// Acepta las dos formas, porque el MSI escribe una y un administrador a mano
// suele escribir la otra:
//   - REG_MULTI_SZ: un host por línea.
//   - REG_SZ: separados por ";" o ",".
//
// Mira las DOS vistas del registro (GDI-804A, 1.8.1). El MSI es de 32 bits y
// en un Windows de 64 su escritura en SOFTWARE\GDILatam\FirmadorGDI termina en
// SOFTWARE\WOW6432Node\GDILatam\FirmadorGDI; este .exe es de 64 bits y, sin
// pedirlo, solo ve la vista de 64. Hasta la 1.8.0 el servidor del municipio
// quedaba escrito donde el programa no miraba y la firma se rechazaba.
//
// Las dos vistas son HKLM: solo un administrador las escribe, así que leer la
// de 32 no reabre FG-001. Si hay valor en las dos (el MSI en una, un
// administrador a mano en la otra), se suman sin repetir.
func Leer() []string {
	return limpiar(unirVistas(
		vista{"64 bits", func() ([]string, bool) {
			return leerVista(registry.LOCAL_MACHINE, claveRegistro, registry.WOW64_64KEY)
		}},
		vista{"32 bits (WOW6432Node)", func() ([]string, bool) {
			return leerVista(registry.LOCAL_MACHINE, claveRegistro, registry.WOW64_32KEY)
		}},
	))
}

// leerVista lee el valor en UNA vista del registro (WOW64_64KEY o
// WOW64_32KEY). Devuelve false si no están la clave o el valor.
func leerVista(raiz registry.Key, clave string, vistaWOW64 uint32) ([]string, bool) {
	k, err := registry.OpenKey(raiz, clave, registry.QUERY_VALUE|vistaWOW64)
	if err != nil {
		// Lo normal en una instalación SaaS: la clave no existe.
		return nil, false
	}
	defer k.Close()

	if valores, _, err := k.GetStringsValue(NombreValor); err == nil {
		return valores, true
	}

	crudo, _, err := k.GetStringValue(NombreValor)
	if err != nil {
		return nil, false
	}
	return strings.FieldsFunc(crudo, func(r rune) bool {
		return r == ';' || r == ',' || r == ' '
	}), true
}
