//go:build windows

package hostsconfig

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

const origen = RutaRegistro + `\` + NombreValor

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
func Leer() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\GDILatam\FirmadorGDI`, registry.QUERY_VALUE)
	if err != nil {
		// Lo normal en una instalación SaaS: la clave no existe.
		return nil
	}
	defer k.Close()

	if valores, _, err := k.GetStringsValue(NombreValor); err == nil {
		return limpiar(valores)
	}

	crudo, _, err := k.GetStringValue(NombreValor)
	if err != nil {
		return nil
	}
	return limpiar(strings.FieldsFunc(crudo, func(r rune) bool {
		return r == ';' || r == ',' || r == ' '
	}))
}
