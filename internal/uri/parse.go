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
	// borrarlas antes deja a ARIES, DEMO y ARG sin firma con token. Ver GDI-533.
	"demo-backend-prd.fly.dev",
	"aries-backend-prd.fly.dev",
	"arg-backend-prd.fly.dev",

	// Dominio propio del backend de DEV (`fly certs list -a gdi-backend-dev`
	// lo da como Issued). Es la forma a la que van los otros tres.
	"enlace.gdilatam.com",

	// Solo para cmd/testserver. Ver FG-008: debería quedar detrás de un build
	// tag; no se toca en este cambio.
	"localhost",
	"127.0.0.1",
}

// isAllowedServletURL exige HTTPS —o HTTP solo contra local— y que el host esté
// en la lista de arriba, escrito completo.
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
	for _, permitido := range HostsPermitidos {
		if host == permitido {
			return true
		}
	}
	return false
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
	if !isAllowedServletURL(p.RtServlet) {
		return fmt.Errorf("rtservlet debe ser HTTPS (o localhost para pruebas): %q", p.RtServlet)
	}
	if p.StServlet == "" {
		return fmt.Errorf("falta parámetro 'stservlet'")
	}
	if !isAllowedServletURL(p.StServlet) {
		return fmt.Errorf("stservlet debe ser HTTPS (o localhost para pruebas): %q", p.StServlet)
	}
	return nil
}
