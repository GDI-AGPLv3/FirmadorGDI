package storage

// GDI-405 — protocolo "al token viaja el digest".
//
// Hasta 1.3.1 el servidor mandaba el PDF entero dentro del envelope (clave
// `dat`), el firmador lo firmaba en la máquina del funcionario y devolvía el PDF
// firmado por el mismo camino. Un expediente de 19 MB viajaba dos veces por una
// conexión municipal para que al token le llegaran, al final, 32 bytes.
//
// Ahora el PDF no sale del servidor. Lo único que cruza la red es:
//
//	firmador → servidor : CERT:<cert DER>          (para que el server prepare)
//	servidor → firmador : PENDING | DIGESTS:[...]  (32 bytes por documento)
//	firmador → servidor : SIGS:[...]               (256 bytes por documento)
//
// El sello visible, el estampado y el armado del CMS los hace el servidor: el
// token solo aporta lo único que nadie más puede aportar, que es la firma RSA de
// los SignedAttributes.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Prefijos del protocolo. Van en texto plano al principio del campo `dat`
// porque el transporte (form-urlencoded, op=put|get) no cambió: es el mismo
// endpoint de siempre y tiene que poder distinguir un mensaje nuevo de un
// "CANCEL" o de un estado de tanda.
const (
	PrefijoCert    = "CERT:"
	PrefijoDigests = "DIGESTS:"
	PrefijoFirmas  = "SIGS:"

	// RespuestaPendiente es lo que contesta el servidor mientras prepara los
	// documentos. Es literal, sin base64 ni JSON.
	RespuestaPendiente = "PENDING"
)

// TamanoDigestSHA256 es el único largo aceptable de un digest a firmar.
//
// La validación no es cosmética: el token firma A CIEGAS lo que se le pase, y
// `tokenSigner.Sign` le antepone el DigestInfo de SHA-256 sin mirar el largo de
// lo que recibe. Si el servidor mandara 40 bytes, el token produciría una firma
// perfectamente válida sobre una estructura que no es un SHA-256 — y el
// funcionario habría firmado cualquier cosa con su token.
const TamanoDigestSHA256 = 32

// Parámetros del polling. El servidor tiene que estampar el número, componer el
// sello y preparar el CMS de cada documento contra Notary; eso tarda.
const (
	IntentosPolling = 20
	EsperaPolling   = 500 * time.Millisecond
)

// DigestItem es un documento listo para firmar: qué sesión es y qué 32 bytes
// hay que meterle al token.
type DigestItem struct {
	ID        string `json:"id"`
	DigestB64 string `json:"digest_b64"`
}

// FirmaItem es la respuesta del token para un documento.
type FirmaItem struct {
	ID     string `json:"id"`
	SigB64 string `json:"sig_b64"`
}

// Digest decodifica el digest y verifica que sea un SHA-256.
//
// Acepta base64 estándar o url-safe, con o sin padding: el envoltorio del
// protocolo es base64url pero estos valores los genera Python del otro lado y
// no hay razón para que una firma se caiga por un guion bajo.
func (d DigestItem) Digest() ([]byte, error) {
	crudo, err := decodificarB64Tolerante(d.DigestB64)
	if err != nil {
		return nil, fmt.Errorf("documento %s: digest en base64 inválido: %w", d.ID, err)
	}
	if len(crudo) != TamanoDigestSHA256 {
		return nil, fmt.Errorf(
			"documento %s: el servidor mandó un digest de %d bytes y un SHA-256 son %d — no se firma",
			d.ID, len(crudo), TamanoDigestSHA256)
	}
	return crudo, nil
}

// decodificarB64Tolerante prueba las cuatro variantes de base64 que puede haber
// mandado el servidor.
func decodificarB64Tolerante(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("vacío")
	}
	codecs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var ultimo error
	for _, c := range codecs {
		b, err := c.DecodeString(s)
		if err == nil {
			return b, nil
		}
		ultimo = err
	}
	return nil, ultimo
}

// CodificarCert arma el `dat` del mensaje CERT: el certificado del token en
// DER, envuelto en base64url sin padding (igual que el PostResult de siempre).
func CodificarCert(certDER []byte) string {
	return PrefijoCert + base64.RawURLEncoding.EncodeToString(certDER)
}

// CodificarFirmas arma el `dat` del mensaje SIGS.
func CodificarFirmas(firmas []FirmaItem) (string, error) {
	if len(firmas) == 0 {
		return "", fmt.Errorf("no hay firmas para enviar")
	}
	crudo, err := json.Marshal(firmas)
	if err != nil {
		return "", fmt.Errorf("no se pudo armar el JSON de firmas: %w", err)
	}
	return PrefijoFirmas + base64.RawURLEncoding.EncodeToString(crudo), nil
}

// ParsearDigests interpreta una respuesta del polling.
//
// Devuelve pendiente=true mientras el servidor sigue preparando. Un cuerpo que
// no sea ni PENDING ni DIGESTS: es un error: puede ser un servidor viejo
// devolviendo el envelope con el PDF, y en ese caso hay que cortar, no esperar.
func ParsearDigests(cuerpo string) (items []DigestItem, pendiente bool, err error) {
	cuerpo = strings.TrimSpace(cuerpo)

	if cuerpo == RespuestaPendiente {
		return nil, true, nil
	}
	if !strings.HasPrefix(cuerpo, PrefijoDigests) {
		return nil, false, fmt.Errorf(
			"el servidor contestó algo que no es %s ni %s (%d bytes)",
			RespuestaPendiente, PrefijoDigests, len(cuerpo))
	}

	crudo, err := decodificarB64Tolerante(strings.TrimPrefix(cuerpo, PrefijoDigests))
	if err != nil {
		return nil, false, fmt.Errorf("la lista de digests no vino en base64 válido: %w", err)
	}
	if err := json.Unmarshal(crudo, &items); err != nil {
		return nil, false, fmt.Errorf("la lista de digests no es JSON válido: %w", err)
	}
	if len(items) == 0 {
		return nil, false, fmt.Errorf("el servidor mandó una lista de digests vacía")
	}
	// El mismo techo que el manifiesto: si el servidor pide firmar mil cosas,
	// algo se rompió del otro lado y el token no es el lugar donde averiguarlo.
	if len(items) > MaxDocumentosManifiesto {
		return nil, false, fmt.Errorf(
			"el servidor pide firmar %d documentos y el máximo es %d",
			len(items), MaxDocumentosManifiesto)
	}
	for _, it := range items {
		if it.ID == "" {
			return nil, false, fmt.Errorf("un documento de la lista vino sin id")
		}
	}
	return items, false, nil
}

// PostCert le manda al servidor el certificado del token para que arranque la
// preparación.
func PostCert(stServlet, sessionID string, certDER []byte) error {
	if len(certDER) == 0 {
		return fmt.Errorf("el token no devolvió certificado")
	}
	return Put(stServlet, sessionID, CodificarCert(certDER))
}

// PostFirmas devuelve las firmas del token, una por documento.
func PostFirmas(stServlet, sessionID string, firmas []FirmaItem) error {
	dat, err := CodificarFirmas(firmas)
	if err != nil {
		return err
	}
	return Put(stServlet, sessionID, dat)
}

// EsperarDigests pollea el retriever hasta que el servidor termine de preparar
// los documentos.
//
// El tope es de IntentosPolling × EsperaPolling (10 s). Si se agota NO se sigue
// esperando en silencio: el usuario ya puso el PIN y tiene que enterarse de que
// la firma no salió, porque del otro lado los números quedan reservados hasta
// que la sesión venza.
func EsperarDigests(rtServlet, id string) ([]DigestItem, error) {
	return esperarDigests(rtServlet, id, IntentosPolling, EsperaPolling)
}

// esperarDigests es EsperarDigests con los tiempos por parámetro, para que los
// tests no tengan que dormir diez segundos para probar el vencimiento.
func esperarDigests(
	rtServlet, id string, intentos int, espera time.Duration,
) ([]DigestItem, error) {
	var ultimoErr error
	for intento := 1; intento <= intentos; intento++ {
		cuerpo, err := Get(rtServlet, id)
		if err != nil {
			// Un error de red suelto no tira la firma abajo: el servidor puede
			// estar reiniciando una instancia. Se reintenta mientras queden
			// intentos y, si se acaban, se reporta el último error real.
			ultimoErr = err
		} else {
			items, pendiente, perr := ParsearDigests(cuerpo)
			if perr != nil {
				return nil, perr
			}
			if !pendiente {
				return items, nil
			}
			ultimoErr = nil
		}
		if intento < intentos {
			time.Sleep(espera)
		}
	}
	total := time.Duration(intentos) * espera
	if ultimoErr != nil {
		return nil, fmt.Errorf(
			"el servidor no llegó a preparar los documentos en %s: %w", total, ultimoErr)
	}
	return nil, fmt.Errorf(
		"el servidor sigue preparando los documentos después de %s — se cancela la firma",
		total)
}
