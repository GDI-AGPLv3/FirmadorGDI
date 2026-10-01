// Package hostsconfig lee los servidores que el administrador autorizó al
// instalar, además de los que vienen compilados en internal/uri.
//
// ── Para qué existe ─────────────────────────────────────────────────────────
//
// El binario trae compilados los hosts de GDI (los cuatro `enlace-*`). Una
// instalación on-premise firma contra el servidor del municipio
// (`api.su-municipio.gob.ar`), que no puede estar en esa lista: no lo conocemos
// al compilar, y hacer una release por cliente no escala.
//
// Entonces el MSI lo pregunta en la instalación y lo guarda acá. Un solo
// instalador sirve para el SaaS y para todos los on-premise.
//
// ── Por qué el registro y no un archivo ─────────────────────────────────────
//
// Porque lo que decide si esto es seguro o es un agujero es QUIÉN puede
// escribirlo.
//
//   - `HKEY_LOCAL_MACHINE` necesita permisos de administrador. El MSI corre
//     elevado, así que puede escribirlo al instalar; después, un usuario común
//     —el funcionario— no puede tocarlo.
//   - Un archivo junto al .exe, una variable de entorno o `HKCU` los escribe el
//     propio usuario. Con cualquiera de esos, una página maliciosa que logre
//     ejecutar algo como el usuario se autoriza sola, y volvemos a FG-001.
//
// El ataque que cerró FG-001 es REMOTO: un link `gdifirma://` con el servidor
// del atacante adentro. Ese atacante no escribe en HKLM. Lo que queda posible es
// la ingeniería social —convencer al área de sistemas de agregar un host—, y
// contra eso la defensa es que el diálogo del PIN muestre SIEMPRE el servidor
// (1.5.0): el funcionario ve el nombre antes de poner el PIN.
//
// ── En macOS ────────────────────────────────────────────────────────────────
//
// No hay registro. El equivalente de HKLM es un archivo bajo /Library, que es
// de root: para escribirlo hace falta `sudo`, y el funcionario —aunque su
// usuario sea administrador de la Mac— no lo cambia sin que el sistema le pida
// la contraseña. El razonamiento es el mismo de arriba, y por eso Leer() no se
// conforma con que el archivo exista: exige que sea de root y que nadie más lo
// pueda escribir (soloLoEscribeRoot). Un archivo ahí con otro dueño o con
// permisos abiertos se IGNORA, con aviso en el log.
package hostsconfig

import (
	"fmt"
	"io/fs"
	"log"
	"strings"
)

// RutaRegistro es dónde vive la lista en Windows, documentado acá para que el
// instalador y el soporte miren el mismo lugar.
const RutaRegistro = `HKLM\SOFTWARE\GDILatam\FirmadorGDI`

// NombreValor es el valor del registro que guarda los hosts.
const NombreValor = "HostsAutorizados"

// RutaArchivoMac es dónde vive la lista en macOS: un host por línea.
const RutaArchivoMac = "/Library/Application Support/GDILatam/FirmadorGDI/" + NombreValor

func limpiar(valores []string) []string {
	out := make([]string, 0, len(valores))
	for _, v := range valores {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) > 0 {
		// Al log, siempre: si el municipio no puede firmar, lo primero que se
		// pregunta es qué host quedó autorizado en esa máquina.
		log.Printf("hosts autorizados en la instalación (%s): %v", origen, out)
	}
	return out
}

// hostsDeTexto saca los hosts del contenido del archivo de macOS: uno por
// línea, o varios separados por ";", "," o espacios. Las líneas que empiezan
// con "#" son comentarios.
func hostsDeTexto(crudo string) []string {
	var hosts []string
	for _, linea := range strings.Split(crudo, "\n") {
		linea = strings.TrimSpace(linea)
		if strings.HasPrefix(linea, "#") {
			continue
		}
		hosts = append(hosts, strings.FieldsFunc(linea, func(r rune) bool {
			return r == ';' || r == ',' || r == ' ' || r == '\t'
		})...)
	}
	return hosts
}

// soloLoEscribeRoot dice si un archivo (o carpeta) con ese dueño y esos
// permisos cumple lo que hace segura a la lista: que la escriba root y nadie
// más. Es la condición que en Windows da HKLM por sí solo.
//
// Vive acá, sin build tag, para que se pueda probar en cualquier máquina: es la
// única línea de defensa entre "lo autorizó sistemas" y "se autorizó solo".
func soloLoEscribeRoot(uid uint32, modo fs.FileMode) error {
	if modo&fs.ModeSymlink != 0 {
		return fmt.Errorf("es un enlace simbólico")
	}
	if uid != 0 {
		return fmt.Errorf("no es de root (uid %d)", uid)
	}
	if modo.Perm()&0o022 != 0 {
		return fmt.Errorf("lo puede escribir alguien que no es root (permisos %o)", modo.Perm())
	}
	return nil
}
