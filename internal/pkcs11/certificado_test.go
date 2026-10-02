package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// tokenFalso es un token de mentira. Con hardware esto no se puede probar sin
// un token que tenga un certificado renovado al lado del viejo; lo que sí se
// puede fijar acá es la DECISIÓN: qué certificado se presenta y con qué clave
// se firma.
type tokenFalso struct {
	objs  []objetoFalso
	tanda int // cuántos objetos devuelve por FindObjects (0 = los que pidan)

	buscando []p11.ObjectHandle
}

type objetoFalso struct {
	clase uint
	attrs map[uint][]byte
}

func (t *tokenFalso) agregar(clase uint, attrs map[uint][]byte) p11.ObjectHandle {
	t.objs = append(t.objs, objetoFalso{clase: clase, attrs: attrs})
	return p11.ObjectHandle(len(t.objs)) // los handles arrancan en 1
}

func (t *tokenFalso) FindObjectsInit(_ p11.SessionHandle, temp []*p11.Attribute) error {
	// CKA_CLASS viaja como un entero de la máquina; se arma igual para comparar.
	t.buscando = nil
	for i, o := range t.objs {
		clase := p11.NewAttribute(p11.CKA_CLASS, o.clase).Value
		if string(clase) == string(temp[0].Value) {
			t.buscando = append(t.buscando, p11.ObjectHandle(i+1))
		}
	}
	return nil
}

func (t *tokenFalso) FindObjects(_ p11.SessionHandle, max int) ([]p11.ObjectHandle, bool, error) {
	n := max
	if t.tanda > 0 && t.tanda < n {
		n = t.tanda
	}
	if n > len(t.buscando) {
		n = len(t.buscando)
	}
	out := t.buscando[:n]
	t.buscando = t.buscando[n:]
	return out, false, nil
}

func (t *tokenFalso) FindObjectsFinal(p11.SessionHandle) error { return nil }

func (t *tokenFalso) GetAttributeValue(
	_ p11.SessionHandle, h p11.ObjectHandle, a []*p11.Attribute,
) ([]*p11.Attribute, error) {
	v, ok := t.objs[int(h)-1].attrs[a[0].Type]
	if !ok {
		return nil, p11.Error(p11.CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return []*p11.Attribute{{Type: a[0].Type, Value: v}}, nil
}

// Generar claves RSA es lo único lento de estos tests: se hacen una vez.
var (
	clavesUnaVez sync.Once
	clavesRSA    []*rsa.PrivateKey
)

func claveRSA(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	clavesUnaVez.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			clavesRSA = append(clavesRSA, k)
		}
	})
	return clavesRSA[i]
}

var hoy = time.Date(2026, 10, 2, 14, 0, 0, 0, time.UTC)

func dias(n int) time.Time { return hoy.AddDate(0, 0, n) }

var serie int64

// certDe arma un certificado para esa clave pública, válido entre esas fechas.
func certDe(t *testing.T, pub any, desde, hasta time.Time, esCA bool) []byte {
	t.Helper()
	serie++
	plantilla := &x509.Certificate{
		SerialNumber:          big.NewInt(serie),
		Subject:               pkix.Name{CommonName: "PEREZ Juana", SerialNumber: "CUIL 27123456789"},
		NotBefore:             desde,
		NotAfter:              hasta,
		BasicConstraintsValid: true,
		IsCA:                  esCA,
	}
	if esCA {
		plantilla.Subject = pkix.Name{CommonName: "AC de prueba"}
		plantilla.KeyUsage = x509.KeyUsageCertSign
	}
	// Lo firma una clave cualquiera: acá nadie valida la cadena.
	der, err := x509.CreateCertificate(rand.Reader, plantilla, plantilla, pub, claveRSA(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// par carga en el token un certificado y su clave privada, como los deja el
// middleware: mismo CKA_ID en los dos, y el módulo en la clave.
func (tk *tokenFalso) par(t *testing.T, id string, k *rsa.PrivateKey, desde, hasta time.Time) (der []byte, clave p11.ObjectHandle) {
	t.Helper()
	der = certDe(t, &k.PublicKey, desde, hasta, false)
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{p11.CKA_VALUE: der, p11.CKA_ID: []byte(id)})
	clave = tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{
		p11.CKA_ID: []byte(id), p11.CKA_MODULUS: k.PublicKey.N.Bytes(),
	})
	return der, clave
}

func elegirEn(tk *tokenFalso) (*certEnToken, p11.ObjectHandle, error) {
	return elegirCertYClave(leerCertificados(tk, 0), leerClaves(tk, 0), hoy)
}

// EL caso que se reportó (producción, 02/10/2026): el funcionario renovó el
// certificado y en el token quedaron los dos, el viejo primero. Hasta la 1.7.0
// se firmaba con el viejo y el servidor rechazaba con "certificado vencido".
func TestConCertificadoViejoYRenovadoSeFirmaConElRenovado(t *testing.T) {
	tk := &tokenFalso{}
	viejo, claveVieja := tk.par(t, "viejo", claveRSA(t, 0), dias(-800), dias(-30))
	nuevo, claveNueva := tk.par(t, "nuevo", claveRSA(t, 1), dias(-40), dias(690))

	elegido, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatalf("hay un certificado vigente con su clave y falló: %v", err)
	}
	if string(elegido.der) == string(viejo) {
		t.Fatal("se eligió el certificado VENCIDO: es el bug que se reportó")
	}
	if string(elegido.der) != string(nuevo) {
		t.Fatal("el certificado elegido no es el renovado")
	}
	// Tan importante como el certificado: la clave tiene que ser LA SUYA. Con el
	// certificado nuevo y la clave vieja la firma no valida.
	if clave == claveVieja {
		t.Fatal("se presenta el certificado renovado pero se firma con la clave del viejo")
	}
	if clave != claveNueva {
		t.Fatalf("la clave elegida (%d) no es la del certificado renovado (%d)", clave, claveNueva)
	}
}

// El orden en que el token devuelve los objetos no puede cambiar el resultado.
func TestElOrdenDelTokenNoCambiaLaEleccion(t *testing.T) {
	tk := &tokenFalso{}
	nuevo, claveNueva := tk.par(t, "nuevo", claveRSA(t, 1), dias(-40), dias(690))
	tk.par(t, "viejo", claveRSA(t, 0), dias(-800), dias(-30))

	elegido, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if string(elegido.der) != string(nuevo) || clave != claveNueva {
		t.Fatal("con el renovado primero se eligió otro certificado u otra clave")
	}
}

// El diálogo del PIN se arma ANTES del login, cuando las claves todavía no se
// ven. Igual tiene que mostrar el vencimiento del certificado renovado: es lo
// que el funcionario mira para saber con qué va a firmar.
func TestElDialogoMuestraElRenovadoSinHaberHechoLogin(t *testing.T) {
	tk := &tokenFalso{}
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 0).PublicKey, dias(-800), dias(-30), false),
	})
	nuevo := certDe(t, &claveRSA(t, 1).PublicKey, dias(-40), dias(690), false)
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{p11.CKA_VALUE: nuevo})

	elegido := elegirCertificado(leerCertificados(tk, 0), hoy)
	if elegido == nil || string(elegido.der) != string(nuevo) {
		t.Fatal("antes del login no se eligió el certificado renovado")
	}
}

// Los tokens suelen traer la cadena (AC raíz, AC emisora) cargada como
// certificados comunes, a veces adelante del de la persona y con un vencimiento
// mucho más lejano. No tienen clave en el token: no se firma con ellos, y
// tampoco pueden ser lo que muestre el diálogo.
func TestLosCertificadosDeLaCadenaNoSeEligen(t *testing.T) {
	tk := &tokenFalso{}
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 2).PublicKey, dias(-3000), dias(5000), true),
	})
	persona, clave := tk.par(t, "persona", claveRSA(t, 0), dias(-40), dias(690))

	antes := elegirCertificado(leerCertificados(tk, 0), hoy)
	if antes == nil || string(antes.der) != string(persona) {
		t.Error("el diálogo mostraría el certificado de la AC en vez del de la persona")
	}

	elegido, k, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if string(elegido.der) != string(persona) || k != clave {
		t.Fatal("se eligió el certificado de la AC")
	}
}

// Si el único certificado está vencido se presenta igual: quien rechaza es el
// servidor, con su reloj. Cortar acá, con el reloj de una PC municipal, dejaría
// sin firmar a alguien con el certificado en regla y la fecha de la máquina mal.
func TestConUnSoloCertificadoVencidoSePresentaIgual(t *testing.T) {
	tk := &tokenFalso{}
	vencido, clave := tk.par(t, "unico", claveRSA(t, 0), dias(-800), dias(-30))

	elegido, k, err := elegirEn(tk)
	if err != nil {
		t.Fatalf("no tiene que cortar del lado del firmador: %v", err)
	}
	if string(elegido.der) != string(vencido) || k != clave {
		t.Fatal("no se eligió el único certificado que hay")
	}
}

// Con el reloj de la máquina en cualquier año —pila agotada, fecha de fábrica—
// ningún certificado parece vigente. Entre el viejo y el renovado tiene que
// seguir ganando el renovado: vence más tarde.
func TestConElRelojMalSigueGanandoElRenovado(t *testing.T) {
	tk := &tokenFalso{}
	tk.par(t, "viejo", claveRSA(t, 0), dias(-800), dias(-30))
	nuevo, claveNueva := tk.par(t, "nuevo", claveRSA(t, 1), dias(-40), dias(690))

	for nombre, reloj := range map[string]time.Time{
		"atrasado diez años":   hoy.AddDate(-10, 0, 0),
		"adelantado diez años": hoy.AddDate(10, 0, 0),
	} {
		elegido, clave, err := elegirCertYClave(leerCertificados(tk, 0), leerClaves(tk, 0), reloj)
		if err != nil {
			t.Fatalf("reloj %s: %v", nombre, err)
		}
		if string(elegido.der) != string(nuevo) || clave != claveNueva {
			t.Errorf("reloj %s: no se eligió el certificado renovado", nombre)
		}
	}
}

// El emparejamiento manda por el módulo RSA, no por la etiqueta: un token mal
// cargado puede tener los CKA_ID cruzados, y firmar con la clave que DICE ser
// de ese certificado y no lo es da una firma que no valida.
func TestLaClaveSeEmparejaPorElModuloAunqueElIDDigaOtraCosa(t *testing.T) {
	tk := &tokenFalso{}
	kVieja, kNueva := claveRSA(t, 0), claveRSA(t, 1)
	// IDs cruzados: cada certificado lleva el ID de la clave del otro.
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &kVieja.PublicKey, dias(-800), dias(-30), false), p11.CKA_ID: []byte("B"),
	})
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &kNueva.PublicKey, dias(-40), dias(690), false), p11.CKA_ID: []byte("A"),
	})
	tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{p11.CKA_ID: []byte("A"), p11.CKA_MODULUS: kVieja.PublicKey.N.Bytes()})
	// Con ceros adelante, como lo devuelven algunos drivers.
	claveNueva := tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{
		p11.CKA_ID: []byte("B"), p11.CKA_MODULUS: append([]byte{0, 0}, kNueva.PublicKey.N.Bytes()...),
	})

	_, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if clave != claveNueva {
		t.Fatal("se siguió el CKA_ID en vez del módulo: la clave no es la del certificado")
	}
}

// Un driver que no deja leer el módulo de la clave: queda el CKA_ID.
func TestSinModuloLaClaveSeEmparejaPorElID(t *testing.T) {
	tk := &tokenFalso{}
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 0).PublicKey, dias(-800), dias(-30), false), p11.CKA_ID: []byte("viejo"),
	})
	nuevo := certDe(t, &claveRSA(t, 1).PublicKey, dias(-40), dias(690), false)
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{p11.CKA_VALUE: nuevo, p11.CKA_ID: []byte("nuevo")})
	tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{p11.CKA_ID: []byte("viejo")})
	claveNueva := tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{p11.CKA_ID: []byte("nuevo")})

	elegido, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if string(elegido.der) != string(nuevo) || clave != claveNueva {
		t.Fatal("sin módulo no se emparejó por CKA_ID")
	}
}

// El token que no informa nada de su clave (ni módulo ni ID) y tiene una sola:
// no hay nada que elegir y tiene que seguir andando como hasta la 1.7.0.
func TestConUnaSolaClaveSinDatosSeSigueFirmando(t *testing.T) {
	tk := &tokenFalso{}
	der := certDe(t, &claveRSA(t, 0).PublicKey, dias(-40), dias(690), false)
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{p11.CKA_VALUE: der})
	unica := tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{})

	elegido, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatalf("un token con un certificado y una clave dejó de andar: %v", err)
	}
	if string(elegido.der) != string(der) || clave != unica {
		t.Fatal("no se usó el único certificado con la única clave")
	}
}

// Con varias claves y sin forma de saber cuál es de qué certificado no se
// adivina: la que sale mal es una firma que no valida.
func TestConVariasClavesSinDatosNoSeAdivina(t *testing.T) {
	tk := &tokenFalso{}
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 0).PublicKey, dias(-800), dias(-30), false),
	})
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 1).PublicKey, dias(-40), dias(690), false),
	})
	tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{})
	tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{})

	if _, _, err := elegirEn(tk); err == nil {
		t.Fatal("se eligió una clave al azar")
	}
}

// Los dos errores de siempre siguen siendo dos: token sin certificado no es lo
// mismo que token sin clave.
func TestTokenSinCertificadoOSinClave(t *testing.T) {
	vacio := &tokenFalso{}
	if _, _, err := elegirEn(vacio); !errors.Is(err, ErrSinCertificado) {
		t.Errorf("token vacío: se esperaba ErrSinCertificado y vino: %v", err)
	}

	sinClave := &tokenFalso{}
	sinClave.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &claveRSA(t, 0).PublicKey, dias(-40), dias(690), false),
	})
	if _, _, err := elegirEn(sinClave); !errors.Is(err, ErrSinClave) {
		t.Errorf("token sin clave: se esperaba ErrSinClave y vino: %v", err)
	}
}

// El programa solo firma RSA (tokenSigner). Un certificado de curva elíptica en
// el token no puede ganarle al RSA por vencer más tarde: Signer() rompería.
func TestUnCertificadoQueNoEsRSANoSeElige(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tk := &tokenFalso{}
	tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
		p11.CKA_VALUE: certDe(t, &ec.PublicKey, dias(-40), dias(3000), false), p11.CKA_ID: []byte("ec"),
	})
	tk.agregar(p11.CKO_PRIVATE_KEY, map[uint][]byte{p11.CKA_ID: []byte("ec")})
	rsaDER, claveRSAEnToken := tk.par(t, "rsa", claveRSA(t, 0), dias(-40), dias(690))

	elegido, clave, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if string(elegido.der) != string(rsaDER) || clave != claveRSAEnToken {
		t.Fatal("se eligió un certificado que no es RSA")
	}
}

// Hasta la 1.7.0 se pedía UNA tanda de objetos y lo que no entraba no existía.
// Un token con la cadena completa cargada y un driver que entrega de a pocos
// dejaba afuera justo el certificado de la persona.
func TestSeLeenTodosLosObjetosAunqueElTokenLosEntregueDeAPocos(t *testing.T) {
	tk := &tokenFalso{tanda: 2}
	for range 12 {
		tk.agregar(p11.CKO_CERTIFICATE, map[uint][]byte{
			p11.CKA_VALUE: certDe(t, &claveRSA(t, 2).PublicKey, dias(-3000), dias(5000), true),
		})
	}
	persona, clave := tk.par(t, "persona", claveRSA(t, 0), dias(-40), dias(690))

	if n := len(leerCertificados(tk, 0)); n != 13 {
		t.Fatalf("el token tiene 13 certificados y se leyeron %d", n)
	}
	elegido, k, err := elegirEn(tk)
	if err != nil {
		t.Fatal(err)
	}
	if string(elegido.der) != string(persona) || k != clave {
		t.Fatal("no se llegó al certificado de la persona, que estaba al final")
	}
}
