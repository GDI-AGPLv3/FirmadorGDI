// Package pkcs11 maneja la interacción con tokens hardware via PKCS#11.
// Validado con ePass2003 Feitian, driver eps2003csp11.dll.
package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// ErrTokenLocked se devuelve cuando el token está bloqueado por demasiados PINs incorrectos.
var ErrTokenLocked = errors.New("token bloqueado por PIN incorrecto demasiadas veces")

// KnownDrivers (los drivers conocidos, que se prueban en orden hasta encontrar
// uno que vea un token conectado) está en drivers_<plataforma>.go: las rutas son
// las del middleware de cada fabricante y no tienen nada en común entre sistemas.

// Token representa una sesión abierta con un token PKCS#11.
type Token struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	privKey p11.ObjectHandle
	cert    *x509.Certificate
	certDER []byte

	// mostrado es el certificado cuyos datos vio el funcionario en el diálogo
	// del PIN, elegido antes del login. Solo para dejar en el log si después se
	// firma con otro.
	mostrado *x509.Certificate
}

// TokenInfo contiene la info legible del token para mostrar en el diálogo.
type TokenInfo struct {
	Label        string
	Manufacturer string
	Subject      string
	SerialNumber string // CUIL/CUIT del titular
	ValidUntil   string // "31/12/2030" — vacío si el cert no es legible sin login
}

// Open detecta el token conectado y abre una sesión.
// Intenta leer el certificado público (sin login) para poblar SerialNumber y ValidUntil.
// Con varios certificados en el token muestra el vigente: ver certificado.go.
// driverPath puede ser "" para autodetectar entre KnownDrivers.
//
// Con varios drivers instalados usa el que VE el token, no el primero que
// carga: ver seleccion.go.
func Open(driverPath string) (*Token, *TokenInfo, error) {
	drivers := KnownDrivers
	if driverPath != "" {
		drivers = []string{driverPath}
	}

	elegido, err := elegirDriver(drivers, cargarModulo)
	if err != nil {
		return nil, nil, err
	}

	t := &Token{ctx: elegido.mod.(ctxModulo).Ctx, session: elegido.session}
	info := &TokenInfo{
		Label:        elegido.info.Label,
		Manufacturer: elegido.info.ManufacturerID,
	}

	// CKO_CERTIFICATE son objetos públicos: se leen sin login para poblar el
	// diálogo. Si el token no los muestra todavía, el diálogo sale sin esos datos
	// y el certificado se lee tras el login en loadCertAndKey.
	if c := elegirCertificado(leerCertificados(t.ctx, t.session), time.Now()); c != nil {
		t.mostrado = c.cert
		info.Subject = c.cert.Subject.CommonName
		info.SerialNumber = c.cert.Subject.SerialNumber
		info.ValidUntil = c.cert.NotAfter.Local().Format("02/01/2006")
	}

	return t, info, nil
}

// Login autentica con el PIN del usuario.
func (t *Token) Login(pin string) error {
	if err := t.ctx.Login(t.session, p11.CKU_USER, pin); err != nil {
		if p11Err, ok := err.(p11.Error); ok {
			switch p11Err {
			case p11.CKR_PIN_INCORRECT:
				return fmt.Errorf("PIN incorrecto")
			case p11.CKR_PIN_LOCKED:
				return ErrTokenLocked
			}
		}
		return fmt.Errorf("login fallido: %w", err)
	}
	return t.loadCertAndKey()
}

// loadCertAndKey elige con qué certificado se firma y se queda con SU clave.
// Con un certificado viejo y uno renovado en el mismo token no es el primero
// que aparece: ver certificado.go.
func (t *Token) loadCertAndKey() error {
	// Se vuelve a leer todo: recién con login se ven las claves privadas, y hay
	// tokens que tampoco muestran antes los certificados.
	certs := leerCertificados(t.ctx, t.session)
	claves := leerClaves(t.ctx, t.session)

	elegido, clave, err := elegirCertYClave(certs, claves, time.Now())
	if err != nil {
		return err
	}
	if t.mostrado != nil && !t.mostrado.Equal(elegido.cert) {
		log.Printf("el certificado con el que se firma (vence el %s) no es el que mostró el diálogo del PIN",
			elegido.cert.NotAfter.Local().Format("02/01/2006"))
	}

	t.cert = elegido.cert
	t.certDER = elegido.der
	t.privKey = clave
	return nil
}

// Certificate devuelve el certificado X.509 del token (disponible tras Login).
func (t *Token) Certificate() *x509.Certificate { return t.cert }

// CertificateDER devuelve el certificado en formato DER.
func (t *Token) CertificateDER() []byte { return t.certDER }

// Signer devuelve un crypto.Signer que usa la clave privada del token.
func (t *Token) Signer() crypto.Signer {
	return &tokenSigner{
		token: t,
		pub:   t.cert.PublicKey.(*rsa.PublicKey),
	}
}

// Close cierra la sesión y libera recursos.
func (t *Token) Close() {
	t.ctx.Logout(t.session)
	t.ctx.CloseSession(t.session)
	t.ctx.Finalize()
	t.ctx.Destroy()
}

// tokenSigner implementa crypto.Signer sobre PKCS#11 C_Sign con CKM_RSA_PKCS.
type tokenSigner struct {
	token *Token
	pub   *rsa.PublicKey
}

func (s *tokenSigner) Public() crypto.PublicKey { return s.pub }

func (s *tokenSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	// DigestInfo SHA-256 (PKCS#1 v1.5, RFC 3447).
	prefix := []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
		0x05, 0x00, 0x04, 0x20,
	}
	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS, nil)}
	if err := s.token.ctx.SignInit(s.token.session, mech, s.token.privKey); err != nil {
		return nil, fmt.Errorf("SignInit: %w", err)
	}
	return s.token.ctx.Sign(s.token.session, append(prefix, digest...))
}
