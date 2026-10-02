package pkcs11

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// Elegir el certificado: con cuál de los que hay en el token se firma.
//
// ── Qué pasaba ──────────────────────────────────────────────────────────────
//
// Hasta la 1.7.0 se usaba EL PRIMER certificado que devolvía el token y LA
// PRIMERA clave privada, sin mirar nada de ninguno de los dos. Un funcionario
// que renueva su certificado se queda con dos en el mismo token —el viejo no se
// borra— y el viejo suele ser el primero. El programa firmaba con ese y el
// servidor rechazaba con "certificado vencido", una y otra vez, a alguien que
// tenía un certificado vigente enchufado.
//
// Pasó de verdad: producción, 02/10/2026, cuatro rechazos seguidos del mismo
// firmante en 17 minutos.
//
// ── Qué se hace ahora ───────────────────────────────────────────────────────
//
// Se leen TODOS los certificados y TODAS las claves privadas, y se elige:
//
//  1. solo entre los certificados que tienen su clave privada en el token (los
//     de la cadena —AC raíz, AC emisora— viajan en el token y no la tienen);
//  2. el que está vigente antes que el que no;
//  3. entre iguales, el que vence más tarde.
//
// Y se firma con LA CLAVE DE ESE certificado, no con la primera: elegir bien el
// certificado y firmar con la clave del otro da una firma que no valida.
//
// La vigencia se mira con el reloj de esta máquina, que puede estar mal. Por eso
// el punto 3 no es un adorno: con el reloj en cualquier año, entre el viejo y el
// renovado sigue ganando el renovado. Quien decide si el certificado sirve es el
// servidor; acá solo se elige cuál presentarle.

// ErrSinCertificado: el token no tiene ningún certificado con el que se pueda firmar.
var ErrSinCertificado = errors.New("no se encontró certificado en el token")

// ErrSinClave: el token no muestra ninguna clave privada.
var ErrSinClave = errors.New("no se encontró clave privada en el token")

// objetos es lo que se le pide al driver para listar lo que hay en el token. Lo
// cumple *p11.Ctx; en los tests, un token de mentira: esto no se puede probar
// con hardware sin tener a mano un token con un certificado renovado.
type objetos interface {
	FindObjectsInit(sh p11.SessionHandle, temp []*p11.Attribute) error
	FindObjects(sh p11.SessionHandle, max int) ([]p11.ObjectHandle, bool, error)
	FindObjectsFinal(sh p11.SessionHandle) error
	GetAttributeValue(sh p11.SessionHandle, o p11.ObjectHandle, a []*p11.Attribute) ([]*p11.Attribute, error)
}

// certEnToken es un certificado tal como está guardado en el token.
type certEnToken struct {
	id   []byte // CKA_ID: lo que lo une a su clave. Puede faltar.
	der  []byte
	cert *x509.Certificate
}

// claveEnToken es una clave privada del token: el handle para firmar y lo que
// permite saber de qué certificado es. La clave en sí no sale nunca.
type claveEnToken struct {
	handle  p11.ObjectHandle
	id      []byte // CKA_ID
	modulus []byte // CKA_MODULUS: público también en una clave privada
}

// maxObjetos corta la lectura si un driver contesta sin parar. Un token real
// tiene un puñado de objetos.
const maxObjetos = 64

// buscar devuelve todos los objetos de esa clase. Pide de a tandas hasta que el
// token no devuelve más: hasta la 1.7.0 se pedía una sola tanda y lo que no
// entraba en ella no existía.
func buscar(o objetos, sh p11.SessionHandle, clase uint) []p11.ObjectHandle {
	if err := o.FindObjectsInit(sh, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, clase),
	}); err != nil {
		return nil
	}
	defer o.FindObjectsFinal(sh)

	var todos []p11.ObjectHandle
	for len(todos) < maxObjetos {
		tanda, _, err := o.FindObjects(sh, 16)
		if err != nil || len(tanda) == 0 {
			break
		}
		todos = append(todos, tanda...)
	}
	return todos
}

// atributo lee UN atributo, o nil si el objeto no lo tiene. Se piden de a uno a
// propósito: pedidos juntos, hay drivers que por uno que falta fallan el pedido
// entero.
func atributo(o objetos, sh p11.SessionHandle, h p11.ObjectHandle, tipo uint) []byte {
	attrs, err := o.GetAttributeValue(sh, h, []*p11.Attribute{p11.NewAttribute(tipo, nil)})
	if err != nil || len(attrs) == 0 {
		return nil
	}
	return attrs[0].Value
}

// leerCertificados devuelve los certificados del token que se pueden leer. Son
// objetos públicos: se ven sin login.
func leerCertificados(o objetos, sh p11.SessionHandle) []certEnToken {
	var certs []certEnToken
	for _, h := range buscar(o, sh, p11.CKO_CERTIFICATE) {
		der := atributo(o, sh, h, p11.CKA_VALUE)
		if len(der) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Printf("el token tiene un certificado que no se puede leer: %v", err)
			continue
		}
		certs = append(certs, certEnToken{id: atributo(o, sh, h, p11.CKA_ID), der: der, cert: cert})
	}
	return certs
}

// leerClaves devuelve las claves privadas del token. Requiere login.
func leerClaves(o objetos, sh p11.SessionHandle) []claveEnToken {
	var claves []claveEnToken
	for _, h := range buscar(o, sh, p11.CKO_PRIVATE_KEY) {
		claves = append(claves, claveEnToken{
			handle:  h,
			id:      atributo(o, sh, h, p11.CKA_ID),
			modulus: atributo(o, sh, h, p11.CKA_MODULUS),
		})
	}
	return claves
}

// vigente dice si el certificado sirve en ese momento.
func vigente(c *x509.Certificate, ahora time.Time) bool {
	return !ahora.Before(c.NotBefore) && !ahora.After(c.NotAfter)
}

// sirveParaFirmar descarta lo que el programa no puede usar: firma RSA
// PKCS#1 v1.5 y nada más (ver tokenSigner).
func sirveParaFirmar(c *x509.Certificate) bool {
	_, esRSA := c.PublicKey.(*rsa.PublicKey)
	return esRSA
}

// mejorQue dice si `a` se prefiere sobre `b`: el de una persona antes que el de
// una autoridad certificante, el vigente antes que el que no, y el que vence más
// tarde.
func mejorQue(a, b *x509.Certificate, ahora time.Time) bool {
	if a.IsCA != b.IsCA {
		return !a.IsCA
	}
	if va, vb := vigente(a, ahora), vigente(b, ahora); va != vb {
		return va
	}
	return a.NotAfter.After(b.NotAfter)
}

// elegirCertificado devuelve el preferido de la lista, o nil si ninguno sirve
// para firmar. Con dos igual de buenos gana el primero.
func elegirCertificado(certs []certEnToken, ahora time.Time) *certEnToken {
	var elegido *certEnToken
	for i := range certs {
		c := &certs[i]
		if !sirveParaFirmar(c.cert) {
			continue
		}
		if elegido == nil || mejorQue(c.cert, elegido.cert, ahora) {
			elegido = c
		}
	}
	return elegido
}

// claveDe busca la clave privada de ese certificado.
//
// Primero por el módulo RSA, que es la verdad: si coincide, esa clave firma lo
// que ese certificado verifica. El CKA_ID es una etiqueta que pone quien cargó
// el token y queda de respaldo, para el driver que no deja leer el módulo.
func claveDe(c *certEnToken, claves []claveEnToken) (p11.ObjectHandle, bool) {
	if pub, ok := c.cert.PublicKey.(*rsa.PublicKey); ok {
		n := pub.N.Bytes()
		for _, k := range claves {
			// El token puede devolver el módulo con ceros adelante.
			if len(k.modulus) > 0 && bytes.Equal(bytes.TrimLeft(k.modulus, "\x00"), n) {
				return k.handle, true
			}
		}
	}
	if len(c.id) > 0 {
		for _, k := range claves {
			if bytes.Equal(k.id, c.id) {
				return k.handle, true
			}
		}
	}
	return 0, false
}

// elegirCertYClave decide con qué certificado se firma y devuelve su clave.
func elegirCertYClave(
	certs []certEnToken, claves []claveEnToken, ahora time.Time,
) (*certEnToken, p11.ObjectHandle, error) {
	if elegirCertificado(certs, ahora) == nil {
		return nil, 0, ErrSinCertificado
	}
	if len(claves) == 0 {
		return nil, 0, ErrSinClave
	}

	// Los que tienen su clave en el token: de ahí sale el certificado.
	var conClave []certEnToken
	for i := range certs {
		if _, ok := claveDe(&certs[i], claves); ok {
			conClave = append(conClave, certs[i])
		}
	}

	if elegido := elegirCertificado(conClave, ahora); elegido != nil {
		clave, _ := claveDe(elegido, claves)
		if n := len(conClave); n > 1 {
			log.Printf("el token tiene %d certificados con clave: se usa el que vence el %s (serie %x)",
				n, elegido.cert.NotAfter.Local().Format("02/01/2006"), elegido.cert.SerialNumber)
		}
		avisarSiNoEstaVigente(elegido.cert, ahora)
		return elegido, clave, nil
	}

	// Ningún certificado se pudo emparejar: el token no deja leer ni el módulo
	// ni el CKA_ID de sus claves. Con una sola clave no hay nada que elegir y se
	// sigue como hasta la 1.7.0. Con varias, firmar sería tirar una moneda —y
	// la que sale mal produce una firma que no valida—, así que se corta.
	if len(claves) > 1 {
		return nil, 0, fmt.Errorf(
			"el token tiene %d claves privadas y no informa a qué certificado corresponde cada una",
			len(claves))
	}
	elegido := elegirCertificado(certs, ahora)
	log.Printf("el token no informa a qué certificado corresponde su clave: se usa la única que hay")
	avisarSiNoEstaVigente(elegido.cert, ahora)
	return elegido, claves[0].handle, nil
}

// avisarSiNoEstaVigente deja en el log por qué el servidor va a rechazar la
// firma. No se corta acá: el reloj de esta máquina puede estar mal, y quien
// decide es el servidor.
func avisarSiNoEstaVigente(c *x509.Certificate, ahora time.Time) {
	if vigente(c, ahora) {
		return
	}
	log.Printf("ATENCIÓN: según el reloj de esta máquina el certificado NO está vigente (válido del %s al %s)",
		c.NotBefore.Local().Format("02/01/2006"), c.NotAfter.Local().Format("02/01/2006"))
}
