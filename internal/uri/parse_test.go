package uri

import (
	"net/url"
	"strings"
	"testing"
)

const servlet = "https%3A%2F%2Fgdi-backend-dev.fly.dev%2Fdigital-signature%2Fstorage"

func uriSign() string {
	return "gdifirma://sign?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
}

func uriBatch() string {
	return "gdifirma://batch?ver=1_1&manifest=MANABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
}

// El flujo de a uno NO se toca: hay municipios firmando así.
func TestSignSigueAndando(t *testing.T) {
	p, err := Parse(uriSign())
	if err != nil {
		t.Fatalf("no parseó una URI de firma normal: %v", err)
	}
	if p.Op != OpSign {
		t.Errorf("Op = %q, se esperaba sign", p.Op)
	}
	if p.FileID != "DATAABC" || p.SessionID != "SESABC" {
		t.Errorf("parseo incorrecto: fileid=%q id=%q", p.FileID, p.SessionID)
	}
}

// Chrome a veces agrega una barra después del host.
func TestSignConBarraDeChrome(t *testing.T) {
	raw := "gdifirma://sign/?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("la barra de Chrome rompió el parseo: %v", err)
	}
	if p.Op != OpSign {
		t.Errorf("Op = %q, se esperaba sign", p.Op)
	}
}

func TestBatchSeReconoce(t *testing.T) {
	p, err := Parse(uriBatch())
	if err != nil {
		t.Fatalf("no parseó una URI de tanda: %v", err)
	}
	if p.Op != OpBatch {
		t.Errorf("Op = %q, se esperaba batch", p.Op)
	}
	if p.Manifest != "MANABC" {
		t.Errorf("manifest = %q", p.Manifest)
	}
	if p.SessionID != "BATABC" {
		t.Errorf("id de la tanda = %q", p.SessionID)
	}
}

// Cada operación exige lo suyo: sin manifiesto no hay tanda que firmar.
func TestBatchSinManifiestoFalla(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó una tanda sin manifiesto")
	}
}

// Y una firma de a una sin fileid tampoco: el mensaje de error tiene que
// seguir siendo el de siempre para no confundir a quien lea el log.
func TestSignSinFileIDFalla(t *testing.T) {
	raw := "gdifirma://sign?ver=1_0&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("aceptó una firma sin fileid")
	}
	if got := err.Error(); got != "falta parámetro 'fileid'" {
		t.Errorf("mensaje inesperado: %q", got)
	}
}

func TestOperacionDesconocida(t *testing.T) {
	raw := "gdifirma://cualquiera?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó una operación que no existe")
	}
}

// Los identificadores son la ÚNICA credencial del endpoint público que usa
// este programa. Alfanuméricos puros, sin excepciones.
func TestManifiestoNoAlfanumericoFalla(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&manifest=MAN-ABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó un manifiesto con guiones")
	}
}

func TestServletTieneQueSerHTTPS(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&manifest=MANABC" +
		"&rtservlet=http%3A%2F%2Fmalo.example.com&stservlet=" + servlet +
		"&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó un servlet en HTTP plano")
	}
}

// El programa queda registrado como el que atiende gdifirma://, así que
// cualquier página que el funcionario abra puede lanzarle un link. Las URLs del
// servidor viajan adentro. Sin lista de hosts, un link ajeno conseguía que
// el token firmara documentos que el funcionario nunca vio — y con la tanda,
// cinco por un solo PIN.
//
// FG-001: este test ANTES consagraba el agujero. Daba por permitido cualquier
// cosa bajo ".fly.dev" —hosting compartido, cuenta gratuita, TLS válido— así
// que protegía justamente lo que había que cerrar. Ahora la lista son hosts
// completos y el test lo verifica en los dos sentidos.
func TestSoloSeLeObedeceALosServidoresPropios(t *testing.T) {
	base := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11"

	// Los hosts reales de los cuatro ambientes, escritos completos.
	permitidos := []string{
		"https://gdi-backend-dev.fly.dev",
		"https://demo-backend-prd.fly.dev",
		"https://aries-backend-prd.fly.dev",
		"https://arg-backend-prd.fly.dev",
		"https://enlace.gdilatam.com",
		"http://localhost:8000",
		"http://127.0.0.1:8000",
	}
	for _, servlet := range permitidos {
		raw := base + "&rtservlet=" + url.QueryEscape(servlet) +
			"&stservlet=" + url.QueryEscape(servlet)
		if _, err := Parse(raw); err != nil {
			t.Errorf("rechazó un servidor propio %q: %v", servlet, err)
		}
	}

	ajenos := []string{
		"https://evil.com",
		"https://gdilatam.com.evil.com",    // el sufijo pegado a otro dominio
		"https://evil.com/?x=gdilatam.com", // el nombre propio en el path
		"https://fly.dev.attacker.net",
		"http://gdilatam.com", // sin TLS y no es local
		"https://192.168.1.50",

		// FG-001, el caso que antes pasaba: fly.dev es hosting compartido.
		"https://firma-muni.fly.dev",
		"https://gdi-backend-dev.attacker.fly.dev",
		"https://cualquiera.fly.dev",

		// Un host propio pero que NO está en la lista tampoco pasa: la política
		// es host completo, no "termina con gdilatam.com".
		"https://gdilatam.com",
		"https://api.gdilatam.com",
		"https://arg.gdilatam.com",

		// Prefijo/sufijo pegado a un host que sí está en la lista.
		"https://enlace.gdilatam.com.evil.net",
		"https://xenlace.gdilatam.com",
	}
	for _, servlet := range ajenos {
		raw := base + "&rtservlet=" + url.QueryEscape(servlet) +
			"&stservlet=" + url.QueryEscape(servlet)
		if _, err := Parse(raw); err == nil {
			t.Errorf("aceptó un servidor ajeno: %q", servlet)
		}
	}
}

// La lista no puede volver a tener sufijos: un solo "." al principio de una
// entrada reabre FG-001 entero.
func TestLaListaNoTieneSufijos(t *testing.T) {
	for _, h := range HostsPermitidos {
		if strings.HasPrefix(h, ".") {
			t.Errorf("HostsPermitidos tiene un sufijo (%q): se compara host completo, un sufijo autoriza subdominios ajenos (FG-001)", h)
		}
		if strings.Contains(h, "*") {
			t.Errorf("HostsPermitidos tiene un wildcard (%q)", h)
		}
	}
}

// La tanda entra por el mismo control: es donde más duele, porque son N firmas
// con un solo PIN.
func TestLaTandaTambienExigeDominioPropio(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&manifest=MAN1&id=BAT1&keystore=PKCS11" +
		"&rtservlet=" + url.QueryEscape("https://evil.com") +
		"&stservlet=" + url.QueryEscape("https://evil.com")

	if _, err := Parse(raw); err == nil {
		t.Fatal("una tanda contra un servidor ajeno pasó el control")
	}
}
