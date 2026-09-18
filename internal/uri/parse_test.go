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

		// GDI-535: el dominio propio de cada ambiente. Es a donde va todo
		// cuando los cuatro backends dejen de armar el enlace con su fly.dev.
		"https://enlace-dev.gdilatam.com",
		"https://enlace-aries.gdilatam.com",
		"https://enlace-arg.gdilatam.com",
		"https://enlace-demo.gdilatam.com",
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

		// El sin-sufijo se dio de baja el 17/09 (DNS y certificado): el nombre
		// limpio apuntando a DEV confundía. Si vuelve, se agrega a propósito.
		"https://enlace.gdilatam.com",

		// Prefijo/sufijo pegado a un host que sí está en la lista.
		"https://enlace-arg.gdilatam.com.evil.net",
		"https://xenlace-arg.gdilatam.com",
		"https://enlace-arg.gdilatam.com.br",
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

// El mensaje de error tiene que decir la verdad: "no está autorizado" cuando el
// problema es el host, y "debe ser HTTPS" solo cuando de verdad no es HTTPS.
//
// Nace de un caso real (18/09/2026): el backend de DEV empezó a armar el enlace
// con https://enlace-dev.gdilatam.com/... —HTTPS válido— y la 1.4.3, que no
// tenía ese host, lo rechazó con "rtservlet debe ser HTTPS". El diálogo mandó a
// revisar el certificado cuando el problema era la lista de hosts.
func TestElErrorDiceElMotivoReal(t *testing.T) {
	base := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11"

	casos := []struct {
		nombre  string
		servlet string
		espera  string
	}{
		{"host no autorizado, pero HTTPS", "https://ajeno.example.com", "no está autorizado"},
		{"host propio de otro ambiente mal escrito", "https://enlace-xxx.gdilatam.com", "no está autorizado"},
		{"de verdad no es HTTPS", "http://ajeno.example.com", "debe ser HTTPS"},
		{"host autorizado pero sin TLS", "http://enlace-arg.gdilatam.com", "debe ser HTTPS"},
	}

	for _, c := range casos {
		raw := base + "&rtservlet=" + url.QueryEscape(c.servlet) +
			"&stservlet=" + url.QueryEscape(c.servlet)
		_, err := Parse(raw)
		if err == nil {
			t.Errorf("%s: aceptó %q", c.nombre, c.servlet)
			continue
		}
		if !strings.Contains(err.Error(), c.espera) {
			t.Errorf("%s: el error dice %q y debería contener %q", c.nombre, err.Error(), c.espera)
		}
	}
}

// El error del host tiene que nombrar el host, que es el dato que sirve para
// entender qué pasó — y para que el funcionario pueda reconocerlo o no.
func TestElErrorNombraElHost(t *testing.T) {
	raw := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11" +
		"&rtservlet=" + url.QueryEscape("https://servidor-raro.example.com") +
		"&stservlet=" + url.QueryEscape("https://servidor-raro.example.com")
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("aceptó un servidor ajeno")
	}
	if !strings.Contains(err.Error(), "servidor-raro.example.com") {
		t.Errorf("el error no nombra el host: %q", err.Error())
	}
}

// El diálogo del PIN muestra a dónde van las firmas, y ese dato sale de acá.
func TestServidorHostSaleDelLink(t *testing.T) {
	casos := map[string]string{
		"https://enlace-arg.gdilatam.com/digital-signature/storage": "enlace-arg.gdilatam.com",
		"https://enlace-dev.gdilatam.com/digital-signature/storage": "enlace-dev.gdilatam.com",
		"http://localhost:8000/digital-signature/storage":           "localhost",
	}
	for servlet, esperado := range casos {
		raw := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11" +
			"&rtservlet=" + url.QueryEscape(servlet) +
			"&stservlet=" + url.QueryEscape(servlet)
		p, err := Parse(raw)
		if err != nil {
			t.Fatalf("no parseo %q: %v", servlet, err)
		}
		if got := p.ServidorHost(); got != esperado {
			t.Errorf("ServidorHost() de %q = %q, se esperaba %q", servlet, got, esperado)
		}
	}
}

// ── Hosts de la instalación (GDI-532) ───────────────────────────────────────
//
// El administrador puede autorizar el servidor de su municipio al instalar. Lo
// que NO puede es meter por esa puerta algo que reabra FG-001: un sufijo, un
// comodín o una URL entera.

func TestElHostDeLaInstalacionSeAcepta(t *testing.T) {
	defer resetHostsDeInstalacion()

	aceptados := AgregarHostsAutorizados([]string{"api.su-municipio.gob.ar"})
	if len(aceptados) != 1 {
		t.Fatalf("no se aceptó el host del municipio: %v", aceptados)
	}

	raw := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11" +
		"&rtservlet=" + url.QueryEscape("https://api.su-municipio.gob.ar/digital-signature/storage") +
		"&stservlet=" + url.QueryEscape("https://api.su-municipio.gob.ar/digital-signature/storage")
	if _, err := Parse(raw); err != nil {
		t.Errorf("rechazó el servidor del municipio ya autorizado: %v", err)
	}
}

// El negativo que importa: por esta puerta no entra nada que autorice a otros.
func TestLaInstalacionNoPuedeMeterSufijosNiComodines(t *testing.T) {
	defer resetHostsDeInstalacion()

	basura := []string{
		".gob.ar",                       // sufijo: autorizaría medio país
		".fly.dev",                      // el sufijo de FG-001, otra vez
		"*.muni.gob.ar",                 // comodín
		"*",                             // todo
		"https://api.muni.gob.ar",       // URL, no host
		"api.muni.gob.ar/algo",          // con path
		"api.muni.gob.ar:8443",          // con puerto
		"api muni.gob.ar",               // con espacio
		"localhost",                     // sin punto: ya está compilado
		"",                              // vacío
	}
	aceptados := AgregarHostsAutorizados(basura)
	if len(aceptados) != 0 {
		t.Errorf("se colaron hosts inválidos: %v", aceptados)
	}

	// y ninguno de esos habilita a un tercero
	for _, servlet := range []string{"https://evil.fly.dev", "https://evil.gob.ar", "https://api.muni.gob.ar"} {
		raw := "gdifirma://sign?ver=1_0&fileid=ABC&id=SES1&keystore=PKCS11" +
			"&rtservlet=" + url.QueryEscape(servlet) + "&stservlet=" + url.QueryEscape(servlet)
		if _, err := Parse(raw); err == nil {
			t.Errorf("quedó autorizado %q después de intentar meter basura en la lista", servlet)
		}
	}
}

// Un host de la instalación no pisa ni duplica los compilados.
func TestLosCompiladosSiguenEstando(t *testing.T) {
	defer resetHostsDeInstalacion()

	antes := len(HostsAutorizados())
	AgregarHostsAutorizados([]string{"api.su-municipio.gob.ar", "api.su-municipio.gob.ar", "enlace-arg.gdilatam.com"})
	despues := HostsAutorizados()

	if len(despues) != antes+1 {
		t.Errorf("se esperaba 1 host nuevo (sin duplicar el repetido ni el ya compilado), antes=%d despues=%d", antes, len(despues))
	}
	for _, compilado := range HostsPermitidos {
		if !contiene(despues, compilado) {
			t.Errorf("desapareció el host compilado %q", compilado)
		}
	}
}

func TestSeNormalizaAMinusculas(t *testing.T) {
	defer resetHostsDeInstalacion()
	AgregarHostsAutorizados([]string{"API.Su-Municipio.GOB.AR"})
	if !contiene(HostsAutorizados(), "api.su-municipio.gob.ar") {
		t.Error("el host no se normalizó a minúsculas")
	}
}

func contiene(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func resetHostsDeInstalacion() { hostsDeInstalacion = nil }
