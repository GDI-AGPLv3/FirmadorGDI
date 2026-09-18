// Package uri parsea y valida URIs del scheme gdifirma://.
// Protocolo compatible con @firma 1.9 (misma estructura que afirma://sign?...).
package uri

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const Scheme = "gdifirma"

var alphanumRE = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// Op es qué pidió el sistema: firmar uno o firmar una tanda.
type Op string

const (
	OpSign  Op = "sign"  // gdifirma://sign?...  — un documento (lo de siempre)
	OpBatch Op = "batch" // gdifirma://batch?... — varios con un solo PIN (GDI-167)
)

// Params contiene los parámetros extraídos de la URI gdifirma://...
type Params struct {
	Op         Op     // sign | batch — sale del host de la URI
	Ver        string
	FileID     string // id del XML en storage (solo en sign)
	Manifest   string // id de la lista de documentos a firmar (solo en batch)
	RtServlet  string // URL donde buscar el XML
	StServlet  string // URL donde postear la firma
	SessionID  string // id de la sesión (en batch, el id de la tanda)
	Keystore   string // PKCS11 | WINDOWS | MAC
}

// Parse extrae los parámetros de una URI gdifirma://.
// Chrome puede agregar una / después del host (gdifirma://sign/ en lugar de gdifirma://sign).
func Parse(raw string) (*Params, error) {
	if !strings.HasPrefix(raw, Scheme+"://") {
		return nil, fmt.Errorf("scheme inválido, se esperaba %s://", Scheme)
	}

	// Normalizar: Chrome convierte gdifirma://sign?... en gdifirma://sign/?...
	// Reemplazamos el scheme para que url.Parse lo acepte como http.
	normalized := "https://" + strings.TrimPrefix(raw, Scheme+"://")
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("URI malformada: %w", err)
	}

	// El host dice qué operación es. Chrome puede dejarlo como "sign/" o "batch/".
	op := Op(strings.Trim(u.Host, "/"))
	if op == "" {
		op = OpSign
	}

	q := u.Query()
	p := &Params{
		Op:        op,
		Ver:       q.Get("ver"),
		FileID:    q.Get("fileid"),
		Manifest:  q.Get("manifest"),
		RtServlet: q.Get("rtservlet"),
		StServlet: q.Get("stservlet"),
		SessionID: q.Get("id"),
		Keystore:  q.Get("keystore"),
	}

	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// HostsPermitidos son los únicos servidores a los que este programa le obedece.
// Se comparan contra el host, UNO POR UNO y exacto: no hay sufijos.
//
// ── Por qué existe esta lista ────────────────────────────────────────────────
//
// Al instalarse, el programa queda registrado como el que atiende gdifirma://.
// Desde ese momento CUALQUIER página que el funcionario abra puede lanzar un
// link de esos, no solo la del municipio: un mail, un aviso, una web cualquiera.
// Y las URLs del servidor viajan DENTRO del link.
//
// Sin esta lista, un link armado por otro decía "bajate estos documentos de mi
// servidor y mandame las firmas a mi servidor". El funcionario veía el diálogo
// del PIN de siempre, lo escribía, y firmaba con su token documentos que nunca
// vio. Con la tanda son cinco firmas por un solo PIN en lugar de una.
//
// Que la lista sea pública no la debilita: no protege por ser secreta, protege
// porque el programa se niega a hablar con cualquier otro.
//
// ── Por qué EXACTOS y no sufijos (FG-001, auditoría 04/09/2026) ──────────────
//
// Acá había ".fly.dev", un SUFIJO, y eso dejaba la puerta igual de abierta que
// no tener lista: fly.dev es hosting compartido —está en la Public Suffix List
// justamente por eso—, así que cualquiera con una cuenta gratuita publicaba
// su-servidor.fly.dev, con TLS válido, y quedaba autorizado. El propio repo trae
// el molde del servidor (cmd/testserver, ~60 líneas). Un digest de 32 bytes
// elegido por el atacante es el SHA-256 de un CMS armado sobre el PDF que él
// quiera: el resultado es una firma PAdES válida, con el certificado de la AC
// ONTI, sobre un documento que el funcionario nunca vio. El binding que hace el
// backend no interviene, porque el backend de GDI no participa de ese ida y
// vuelta.
//
// Por eso ahora se listan HOSTS COMPLETOS. Agregar un ambiente nuevo es agregar
// una línea acá y compilar; es una molestia deliberada, y es más barata que un
// sufijo que autoriza a medio internet.
//
// ── Lo que NO cambia ─────────────────────────────────────────────────────────
//
// El binario sigue siendo agnóstico del ambiente: DEV, HML y PRD están todos en
// esta lista, así que un mismo MSI sigue sirviendo para los tres. Esa propiedad
// —la razón por la que las URLs viajan en la URI en vez de estar compiladas— se
// conserva entera.
//
// ⚠️ Una instalación on-premise con dominio propio queda afuera y necesita que
// se agregue el suyo acá, en una versión nueva. Es el costo asumido: leerlo de
// un archivo de configuración local volvería a abrir la puerta, porque quien
// puede escribir ese archivo puede autorizarse a sí mismo.
var HostsPermitidos = []string{
	// DEV — es el default de AUTOFIRMA_STORAGE_URL en el backend cuando la
	// variable no está seteada, que es el caso de gdi-backend-dev.
	"gdi-backend-dev.fly.dev",

	// PRD — TRANSITORIOS. Están acá porque hoy los tres backends de producción
	// arman la URI con su propio *.fly.dev: se leyó de las apps y vale
	// https://demo-backend-prd.fly.dev/digital-signature/storage (idem ARIES;
	// ARG no se pudo leer y va por el mismo patrón). No tienen dominio propio:
	// `fly certs list` no devuelve ninguno para los tres.
	//
	// El objetivo es que PRD se sirva por *.gdilatam.com y que estas tres
	// líneas se borren. Eso NO se puede hacer desde acá: primero hay que emitir
	// el certificado de cada backend y cambiar su AUTOFIRMA_STORAGE_URL —
	// borrarlas antes deja a ARIES, DEMO y ARG sin firma con token. Ver GDI-535.
	"demo-backend-prd.fly.dev",
	"aries-backend-prd.fly.dev",
	"arg-backend-prd.fly.dev",

	// Los dominios propios, uno por ambiente (GDI-535, 17-18/09/2026). Cada uno
	// tiene su certificado emitido en Fly y su backend detrás; el `enlace.`
	// sin sufijo que estaba acá en la 1.4.3 se dio de baja (DNS y certificado)
	// porque el nombre limpio apuntando a DEV confundía.
	//
	// El backend sirve estos hosts RECORTADOS: solo /health y las rutas de
	// firma; el resto da 404 (HostFilterMiddleware). Por eso el municipio puede
	// habilitar este host en su firewall sin abrir el backend entero.
	"enlace-dev.gdilatam.com",
	"enlace-aries.gdilatam.com",
	"enlace-arg.gdilatam.com",
	"enlace-demo.gdilatam.com",

	// Solo para cmd/testserver. Ver FG-008: debería quedar detrás de un build
	// tag; no se toca en este cambio.
	"localhost",
	"127.0.0.1",
}

// hostsDeInstalacion son los que agregó el administrador al instalar, además de
// los de arriba. Se llenan UNA vez al arrancar, desde donde solo un
// administrador puede escribir (en Windows, HKLM — ver internal/hostsconfig).
//
// ── Por qué esto no reabre FG-001 ────────────────────────────────────────────
//
// El ataque de FG-001 es REMOTO: una página cualquiera lanza un gdifirma:// con
// el servidor del atacante adentro. Ese atacante no puede escribir en HKLM, así
// que no puede agregarse a esta lista. El funcionario tampoco: no es admin de su
// máquina. Lo que sí queda posible es la INGENIERÍA SOCIAL — convencer al área
// de sistemas de agregar un host —, y contra eso la defensa es que el diálogo
// del PIN muestre siempre el servidor (ui.TokenInfo.Servidor).
//
// Por eso NO se lee de un archivo junto al .exe, ni de una variable de entorno,
// ni de HKCU: cualquiera de los tres los escribe el propio usuario, y ahí sí
// volvería el agujero.
var hostsDeInstalacion []string

// AgregarHostsAutorizados suma hosts a la lista, validándolos. Devuelve los que
// aceptó, para que el llamador los loguee: si un host quedó afuera hay que poder
// verlo en el log y no descubrirlo cuando el funcionario no puede firmar.
//
// Rechaza lo que no sea un host pelado: sufijos (".ejemplo.com"), wildcards,
// esquemas, barras, puertos y espacios. Un solo sufijo acá reabriría FG-001.
func AgregarHostsAutorizados(hosts []string) []string {
	aceptados := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if !hostValido(h) {
			continue
		}
		if yaEsta(h) {
			continue
		}
		hostsDeInstalacion = append(hostsDeInstalacion, h)
		aceptados = append(aceptados, h)
	}
	return aceptados
}

// HostsAutorizados devuelve la lista efectiva: los compilados más los de la
// instalación. Es lo que el diálogo y el log pueden mostrar.
func HostsAutorizados() []string {
	todos := make([]string, 0, len(HostsPermitidos)+len(hostsDeInstalacion))
	todos = append(todos, HostsPermitidos...)
	todos = append(todos, hostsDeInstalacion...)
	return todos
}

func hostValido(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.ContainsAny(h, "*/\\ \t:?&=@\"'") {
		return false
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	// localhost y las IP locales ya están compilados; un host de instalación
	// tiene que ser un nombre con punto (api.municipio.gob.ar) o una IP.
	return strings.Contains(h, ".")
}

func yaEsta(h string) bool {
	for _, p := range HostsAutorizados() {
		if p == h {
			return true
		}
	}
	return false
}

// isAllowedServletURL exige HTTPS —o HTTP solo contra local— y que el host esté
// en la lista: los compilados de arriba más los que agregó el administrador al
// instalar (hostsDeInstalacion).
func isAllowedServletURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	if host == "" {
		return false
	}

	esLocal := host == "localhost" || host == "127.0.0.1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && esLocal) {
		return false
	}

	// Comparación EXACTA: sin sufijos, sin HasSuffix. Un "termina con" es lo
	// que hacía que cualquier subdominio de un hosting compartido pasara.
	for _, permitido := range HostsAutorizados() {
		if host == permitido {
			return true
		}
	}
	return false
}

// ServidorHost es el host al que este link le va a mandar las firmas, listo
// para mostrarle al funcionario ANTES de que ponga el PIN. Sale de RtServlet,
// que a esta altura ya pasó por revisarServlet.
//
// Existe porque el diálogo del PIN no decía a dónde iban las firmas: el
// funcionario autorizaba con su token sin ver el servidor. Con la lista de
// hosts eso alcanzaba para el ataque remoto, pero no para el caso en que
// alguien logre que se agregue un host (por ejemplo, convenciendo al área de
// sistemas). Verlo es la defensa que no depende de ninguna lista.
func (p *Params) ServidorHost() string {
	parsed, err := url.Parse(p.RtServlet)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// revisarServlet distingue los DOS motivos por los que una URL se rechaza, que
// hasta la 1.4.3 salían con el mismo texto ("debe ser HTTPS").
//
// Pasó de verdad el 18/09: el backend de DEV empezó a armar el enlace con
// enlace-dev.gdilatam.com —HTTPS y perfectamente válido— y el firmador 1.4.3 lo
// rechazó diciendo "debe ser HTTPS". El mensaje mandaba a revisar el certificado
// cuando el problema era que ese host no estaba en la lista de esa versión.
//
// Un error que miente cuesta más que el error.
func revisarServlet(nombre, crudo string) error {
	parsed, err := url.Parse(crudo)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("%s no es una URL válida: %q", nombre, crudo)
	}

	host := parsed.Hostname()
	esLocal := host == "localhost" || host == "127.0.0.1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && esLocal) {
		return fmt.Errorf("%s debe ser HTTPS (o localhost para pruebas): %q", nombre, crudo)
	}

	if !isAllowedServletURL(crudo) {
		return fmt.Errorf(
			"el servidor %q no está autorizado en esta versión del FirmadorGDI (%s). "+
				"Si es el servidor de tu municipio, hace falta una versión que lo incluya; "+
				"si no lo reconocés, NO firmes: cancelá y avisá a sistemas",
			host, nombre)
	}
	return nil
}

func (p *Params) validate() error {
	// GDI-167: cada operación exige lo suyo. `sign` pide fileid —tal cual
	// siempre—; `batch` pide manifest, que es la lista de lo que hay que firmar.
	switch p.Op {
	case OpSign:
		if p.FileID == "" {
			return fmt.Errorf("falta parámetro 'fileid'")
		}
		if !alphanumRE.MatchString(p.FileID) {
			return fmt.Errorf("fileid debe ser alfanumérico puro (sin guiones ni puntos): %q", p.FileID)
		}
	case OpBatch:
		if p.Manifest == "" {
			return fmt.Errorf("falta parámetro 'manifest'")
		}
		if !alphanumRE.MatchString(p.Manifest) {
			return fmt.Errorf("manifest debe ser alfanumérico puro: %q", p.Manifest)
		}
	default:
		return fmt.Errorf("operación desconocida: %q (se esperaba sign o batch)", p.Op)
	}
	if p.SessionID == "" {
		return fmt.Errorf("falta parámetro 'id'")
	}
	if !alphanumRE.MatchString(p.SessionID) {
		return fmt.Errorf("id debe ser alfanumérico puro: %q", p.SessionID)
	}
	if p.RtServlet == "" {
		return fmt.Errorf("falta parámetro 'rtservlet'")
	}
	if err := revisarServlet("rtservlet", p.RtServlet); err != nil {
		return err
	}
	if p.StServlet == "" {
		return fmt.Errorf("falta parámetro 'stservlet'")
	}
	if err := revisarServlet("stservlet", p.StServlet); err != nil {
		return err
	}
	return nil
}
