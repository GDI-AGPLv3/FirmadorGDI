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

	p11 "github.com/miekg/pkcs11"
)

// ErrTokenLocked se devuelve cuando el token está bloqueado por demasiados PINs incorrectos.
var ErrTokenLocked = errors.New("token bloqueado por PIN incorrecto demasiadas veces")

// KnownDrivers (los drivers conocidos, que se prueban en orden hasta encontrar
// uno que cargue) está en drivers_<plataforma>.go: las rutas son las del
// middleware de cada fabricante y no tienen nada en común entre sistemas.

// Token representa una sesión abierta con un token PKCS#11.
type Token struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	privKey p11.ObjectHandle
	cert    *x509.Certificate
	certDER []byte
}

// TokenInfo contiene la info legible del token para mostrar en el diálogo.
type TokenInfo struct {
	Label        string
	Manufacturer string
	Subject      string
	SerialNumber string // CUIL/CUIT del titular
	ValidUntil   string // "31/12/2030" — vacío si el cert no es legible sin login
}

// Open detecta el primer token conectado y abre una sesión.
// Intenta leer el certificado público (sin login) para poblar SerialNumber y ValidUntil.
// driverPath puede ser "" para autodetectar entre KnownDrivers.
func Open(driverPath string) (*Token, *TokenInfo, error) {
	drivers := KnownDrivers
	if driverPath != "" {
		drivers = []string{driverPath}
	}

	var ctx *p11.Ctx
	for _, d := range drivers {
		c := p11.New(d)
		if c == nil {
			continue
		}
		if err := c.Initialize(); err != nil {
			c.Destroy()
			continue
		}
		ctx = c
		break
	}
	if ctx == nil {
		return nil, nil, fmt.Errorf("no se encontró driver PKCS#11 compatible")
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		return nil, nil, fmt.Errorf("no hay tokens conectados")
	}

	tokenInfo, err := ctx.GetTokenInfo(slots[0])
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, nil, fmt.Errorf("GetTokenInfo: %w", err)
	}

	session, err := ctx.OpenSession(slots[0], p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, nil, fmt.Errorf("OpenSession: %w", err)
	}

	t := &Token{ctx: ctx, session: session}
	info := &TokenInfo{
		Label:        tokenInfo.Label,
		Manufacturer: tokenInfo.ManufacturerID,
	}

	// CKO_CERTIFICATE son objetos públicos — intentar leer sin login para poblar el diálogo.
	_ = t.tryReadPublicCert(info) // error no es fatal, se lee tras login en loadCertAndKey

	return t, info, nil
}

// tryReadPublicCert intenta leer el certificado sin login (objetos públicos en PKCS#11).
// Popula info.Subject, info.SerialNumber e info.ValidUntil si tiene éxito.
func (t *Token) tryReadPublicCert(info *TokenInfo) error {
	t.ctx.FindObjectsInit(t.session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
	})
	certs, _, err := t.ctx.FindObjects(t.session, 10)
	t.ctx.FindObjectsFinal(t.session)

	if err != nil || len(certs) == 0 {
		return fmt.Errorf("no hay certs legibles sin login")
	}

	attrs, err := t.ctx.GetAttributeValue(t.session, certs[0], []*p11.Attribute{
		p11.NewAttribute(p11.CKA_VALUE, nil),
	})
	if err != nil {
		return fmt.Errorf("GetAttributeValue: %w", err)
	}

	cert, err := x509.ParseCertificate(attrs[0].Value)
	if err != nil {
		return fmt.Errorf("ParseCertificate: %w", err)
	}

	// Guardar para reusar en loadCertAndKey (evita releer tras login).
	t.certDER = attrs[0].Value
	t.cert = cert

	info.Subject = cert.Subject.CommonName
	info.SerialNumber = cert.Subject.SerialNumber
	info.ValidUntil = cert.NotAfter.Local().Format("02/01/2006")
	return nil
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

func (t *Token) loadCertAndKey() error {
	// Si tryReadPublicCert ya cargó el cert, solo necesitamos la clave privada.
	if t.cert == nil {
		t.ctx.FindObjectsInit(t.session, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
		})
		certs, _, _ := t.ctx.FindObjects(t.session, 10)
		t.ctx.FindObjectsFinal(t.session)

		if len(certs) == 0 {
			return fmt.Errorf("no se encontró certificado en el token")
		}

		attrs, err := t.ctx.GetAttributeValue(t.session, certs[0], []*p11.Attribute{
			p11.NewAttribute(p11.CKA_VALUE, nil),
		})
		if err != nil {
			return fmt.Errorf("GetAttributeValue cert: %w", err)
		}
		t.certDER = attrs[0].Value
		cert, err := x509.ParseCertificate(t.certDER)
		if err != nil {
			return fmt.Errorf("ParseCertificate: %w", err)
		}
		t.cert = cert
	}

	// Leer handle de clave privada (requiere login).
	t.ctx.FindObjectsInit(t.session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
	})
	keys, _, _ := t.ctx.FindObjects(t.session, 5)
	t.ctx.FindObjectsFinal(t.session)

	if len(keys) == 0 {
		return fmt.Errorf("no se encontró clave privada en el token")
	}
	t.privKey = keys[0]
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
