//go:build darwin

package hostsconfig

import (
	"log"
	"os"
	"path/filepath"
	"syscall"
)

const origen = RutaArchivoMac

// Leer devuelve los hosts que el administrador autorizó en esta Mac.
//
// Soft-fail a propósito, igual que en Windows: si el archivo no existe —que es
// el caso NORMAL de una instalación SaaS— devuelve vacío y el programa sigue
// con los hosts compilados. Un error leyéndolo nunca puede impedir firmar.
//
// El archivo lleva un host por línea; también se aceptan separados por ";" o
// ",". Las líneas que empiezan con "#" son comentarios.
func Leer() []string {
	return leerArchivo(RutaArchivoMac)
}

func leerArchivo(ruta string) []string {
	// Se revisan los DOS: el archivo y la carpeta que lo contiene. Con una
	// carpeta que el usuario puede escribir, el archivo de root se reemplaza
	// por otro sin tocarlo.
	for _, p := range []string{filepath.Dir(ruta), ruta} {
		info, err := os.Lstat(p)
		if err != nil {
			// Lo normal en una instalación SaaS: no existe.
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			log.Printf("ATENCION: no se pudo saber de quién es %s; se ignora la lista de hosts de la instalación", p)
			return nil
		}
		if err := soloLoEscribeRoot(st.Uid, info.Mode()); err != nil {
			log.Printf("ATENCION: se IGNORA la lista de hosts de la instalación: %s %v", p, err)
			return nil
		}
	}

	crudo, err := os.ReadFile(ruta)
	if err != nil {
		log.Printf("ATENCION: no se pudo leer %s: %v", ruta, err)
		return nil
	}

	return limpiar(hostsDeTexto(string(crudo)))
}
