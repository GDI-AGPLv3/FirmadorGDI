package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func digestsB64(t *testing.T, items []DigestItem) string {
	t.Helper()
	crudo, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("no se pudo armar el JSON de prueba: %v", err)
	}
	return PrefijoDigests + base64.RawURLEncoding.EncodeToString(crudo)
}

func digestDe(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// El certificado es lo único que el firmador manda antes de firmar: si se
// codifica de una forma que el servidor no sabe leer, la preparación no
// arranca y el funcionario ya puso el PIN.
func TestElCertViajaEnBase64URLSinPadding(t *testing.T) {
	der := []byte{0x30, 0x82, 0x01, 0xFF, 0xFE, 0x00, 0x7F}

	dat := CodificarCert(der)
	if !strings.HasPrefix(dat, PrefijoCert) {
		t.Fatalf("el mensaje no arranca con %q: %q", PrefijoCert, dat)
	}
	cuerpo := strings.TrimPrefix(dat, PrefijoCert)
	if strings.Contains(cuerpo, "=") {
		t.Errorf("el base64url no debería llevar padding: %q", cuerpo)
	}

	vuelta, err := base64.RawURLEncoding.DecodeString(cuerpo)
	if err != nil {
		t.Fatalf("no se pudo decodificar lo que se manda: %v", err)
	}
	if !bytes.Equal(vuelta, der) {
		t.Errorf("el DER no sobrevivió el viaje: %x != %x", vuelta, der)
	}
}

// El token firma A CIEGAS lo que se le pase: tokenSigner.Sign le antepone el
// DigestInfo de SHA-256 sin mirar el largo. Un digest de otro tamaño produce
// una firma válida sobre una estructura que no es un SHA-256 — el funcionario
// habría firmado cualquier cosa con su token. Por eso el largo se valida ACÁ,
// antes de llegar al token.
func TestUnDigestQueNoMide32BytesNoSeFirma(t *testing.T) {
	for _, largo := range []int{1, 20, 31, 33, 64} {
		d := DigestItem{ID: "SES1", DigestB64: digestDe(t, largo)}

		_, err := d.Digest()
		if err == nil {
			t.Fatalf("aceptó un digest de %d bytes", largo)
		}
		if !strings.Contains(err.Error(), "32") {
			t.Errorf("el error de %d bytes no dice cuál es el largo esperado: %v", largo, err)
		}
	}
}

func TestElDigestDe32BytesPasaYVuelveIgual(t *testing.T) {
	crudo := bytes.Repeat([]byte{0xAB}, TamanoDigestSHA256)
	d := DigestItem{ID: "SES1", DigestB64: base64.StdEncoding.EncodeToString(crudo)}

	vuelta, err := d.Digest()
	if err != nil {
		t.Fatalf("rechazó un SHA-256 legítimo: %v", err)
	}
	if !bytes.Equal(vuelta, crudo) {
		t.Errorf("el digest cambió en el camino: %x != %x", vuelta, crudo)
	}
}

// Del otro lado el digest lo codifica Python y el contrato no fija cuál de las
// variantes de base64 usa. Los 32 bytes son los mismos en las cuatro: una firma
// no se puede caer por un guion bajo.
func TestElDigestSeAceptaEnCualquierVarianteDeBase64(t *testing.T) {
	// Bytes elegidos para que el base64 estándar traiga "+" y "/" y el url-safe
	// los reemplace: si el decodificador no fuera tolerante, estos discriminan.
	crudo := bytes.Repeat([]byte{0xFB, 0xEF, 0xBE}, 10)
	crudo = append(crudo, 0xFF, 0xFE)
	if len(crudo) != TamanoDigestSHA256 {
		t.Fatalf("el caso de prueba tiene %d bytes y tienen que ser 32", len(crudo))
	}

	variantes := map[string]string{
		"estándar":         base64.StdEncoding.EncodeToString(crudo),
		"estándar sin pad": base64.RawStdEncoding.EncodeToString(crudo),
		"url-safe":         base64.URLEncoding.EncodeToString(crudo),
		"url-safe sin pad": base64.RawURLEncoding.EncodeToString(crudo),
	}
	for nombre, b64 := range variantes {
		vuelta, err := DigestItem{ID: "SES1", DigestB64: b64}.Digest()
		if err != nil {
			t.Errorf("%s (%q): %v", nombre, b64, err)
			continue
		}
		if !bytes.Equal(vuelta, crudo) {
			t.Errorf("%s: decodificó otra cosa", nombre)
		}
	}
}

func TestPendingNoEsUnError(t *testing.T) {
	items, pendiente, err := ParsearDigests("PENDING")
	if err != nil {
		t.Fatalf("PENDING dio error: %v", err)
	}
	if !pendiente {
		t.Error("no reconoció PENDING como 'todavía no'")
	}
	if items != nil {
		t.Errorf("devolvió documentos con PENDING: %v", items)
	}
}

func TestLaListaDeDigestsSeParsea(t *testing.T) {
	esperados := []DigestItem{
		{ID: "SES1", DigestB64: digestDe(t, TamanoDigestSHA256)},
		{ID: "SES2", DigestB64: digestDe(t, TamanoDigestSHA256)},
	}

	items, pendiente, err := ParsearDigests(digestsB64(t, esperados))
	if err != nil {
		t.Fatalf("no parseó una lista válida: %v", err)
	}
	if pendiente {
		t.Fatal("dijo que estaba pendiente y traía documentos")
	}
	if len(items) != 2 {
		t.Fatalf("trajo %d documentos y eran 2", len(items))
	}
	// Los ids son lo que después empareja cada firma con su documento: si se
	// perdieran o se mezclaran, cada firma iría al expediente equivocado.
	if items[0].ID != "SES1" || items[1].ID != "SES2" {
		t.Errorf("los ids no mapearon: %+v", items)
	}
	if items[0].DigestB64 == items[1].DigestB64 {
		t.Fatal("el caso de prueba no discrimina: los dos digests son iguales")
	}
	if items[0].DigestB64 != esperados[0].DigestB64 {
		t.Errorf("el digest del primer documento no es el que mandó el servidor")
	}
}

// Un servidor viejo contesta el polling con el envelope que trae el PDF. Eso no
// es "todavía no": es un servidor que no habla este protocolo, y esperarlo
// diez segundos para después fallar igual no ayuda a nadie.
func TestUnaRespuestaQueNoEsDelProtocoloCortaEnSeco(t *testing.T) {
	envelopeViejo := base64.StdEncoding.EncodeToString(
		[]byte(`<op><e k="dat" v="JVBERi0xLjQK"/></op>`))

	_, pendiente, err := ParsearDigests(envelopeViejo)
	if err == nil {
		t.Fatal("aceptó un envelope viejo como respuesta del polling")
	}
	if pendiente {
		t.Error("se quedó esperando a un servidor que nunca va a contestar DIGESTS")
	}
}

func TestUnaListaVaciaEsError(t *testing.T) {
	if _, _, err := ParsearDigests(digestsB64(t, []DigestItem{})); err == nil {
		t.Fatal("aceptó una lista de digests vacía")
	}
}

func TestUnDocumentoSinIdEsError(t *testing.T) {
	lista := []DigestItem{{ID: "", DigestB64: digestDe(t, TamanoDigestSHA256)}}

	if _, _, err := ParsearDigests(digestsB64(t, lista)); err == nil {
		t.Fatal("aceptó un documento sin id: la firma no tendría a dónde volver")
	}
}

// El mismo techo que el manifiesto, por la misma razón: el número de firmas que
// se le piden al token no puede salir de lo que diga el servidor sin control.
func TestLaListaDeDigestsTieneTope(t *testing.T) {
	lista := make([]DigestItem, MaxDocumentosManifiesto+1)
	for i := range lista {
		lista[i] = DigestItem{ID: fmt.Sprintf("SES%d", i), DigestB64: digestDe(t, TamanoDigestSHA256)}
	}

	if _, _, err := ParsearDigests(digestsB64(t, lista)); err == nil {
		t.Fatalf("aceptó %d documentos y el máximo es %d",
			len(lista), MaxDocumentosManifiesto)
	}
}

func TestLasFirmasViajanConSuId(t *testing.T) {
	firmas := []FirmaItem{
		{ID: "SES1", SigB64: "AAAA"},
		{ID: "SES2", SigB64: "BBBB"},
	}

	dat, err := CodificarFirmas(firmas)
	if err != nil {
		t.Fatalf("no se pudieron codificar: %v", err)
	}
	if !strings.HasPrefix(dat, PrefijoFirmas) {
		t.Fatalf("el mensaje no arranca con %q: %q", PrefijoFirmas, dat)
	}

	crudo, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(dat, PrefijoFirmas))
	if err != nil {
		t.Fatalf("lo que se manda no es base64url válido: %v", err)
	}
	var vuelta []FirmaItem
	if err := json.Unmarshal(crudo, &vuelta); err != nil {
		t.Fatalf("lo que se manda no es JSON válido: %v", err)
	}
	if len(vuelta) != 2 || vuelta[0].ID != "SES1" || vuelta[1].SigB64 != "BBBB" {
		t.Errorf("las firmas no sobrevivieron el viaje: %+v", vuelta)
	}
}

func TestNoSeMandaUnSIGSVacio(t *testing.T) {
	if _, err := CodificarFirmas(nil); err == nil {
		t.Fatal("armó un SIGS sin ninguna firma adentro")
	}
}

// El servidor tarda: tiene que estampar el número, componer el sello y armar el
// CMS de cada documento contra Notary. El cliente NO puede rendirse en el
// primer PENDING.
func TestElPollingEsperaMientrasElServidorPrepara(t *testing.T) {
	var pedidos atomic.Int32
	lista := []DigestItem{{ID: "SES1", DigestB64: digestDe(t, TamanoDigestSHA256)}}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := pedidos.Add(1); n <= 3 {
			fmt.Fprint(w, RespuestaPendiente)
			return
		}
		fmt.Fprint(w, digestsB64(t, lista))
	}))
	defer s.Close()

	items, err := esperarDigests(s.URL, "SES1", time.Second, time.Millisecond, 2*time.Millisecond)
	if err != nil {
		t.Fatalf("se rindió antes de que el servidor terminara: %v", err)
	}
	if len(items) != 1 || items[0].ID != "SES1" {
		t.Errorf("no trajo el documento preparado: %+v", items)
	}
	if pedidos.Load() != 4 {
		t.Errorf("polleó %d veces y esperaba 4", pedidos.Load())
	}
}

// Si se agota la espera hay que fallar y cancelar, no colgar: el funcionario ya
// puso el PIN y del otro lado los números quedan reservados.
func TestElPollingSeRindeYAvisa(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, RespuestaPendiente)
	}))
	defer s.Close()

	arranque := time.Now()
	_, err := esperarDigests(s.URL, "SES1", 50*time.Millisecond, time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("esperó para siempre a un servidor que nunca termina")
	}
	// El presupuesto es un piso, no solo un techo. Rendirse antes es lo que
	// dejaba números reservados con el trabajo ya hecho del otro lado.
	if tardo := time.Since(arranque); tardo < 50*time.Millisecond {
		t.Errorf("se rindió a los %s y el presupuesto era 50ms", tardo)
	}
	if !strings.Contains(err.Error(), "tardando más de lo normal") {
		t.Errorf("el error no le dice al funcionario qué está pasando: %v", err)
	}
	if !strings.Contains(err.Error(), "de nuevo") {
		t.Errorf("el error no le dice que puede reintentar: %v", err)
	}
}

// El caso feliz —el servidor ya tenía los digests listos— no puede pagar ni un
// milisegundo de espera: el presupuesto largo está para el cold-start, no para
// meterle latencia a la firma normal.
func TestElCasoFelizNoEsperaNada(t *testing.T) {
	var pedidos atomic.Int32
	lista := []DigestItem{{ID: "SES1", DigestB64: digestDe(t, TamanoDigestSHA256)}}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pedidos.Add(1)
		fmt.Fprint(w, digestsB64(t, lista))
	}))
	defer s.Close()

	// Espera inicial absurda a propósito: si el código durmiera ANTES de
	// preguntar, este test tardaría un minuto en vez de milisegundos.
	arranque := time.Now()
	if _, err := esperarDigests(s.URL, "SES1", time.Minute, time.Minute, time.Minute); err != nil {
		t.Fatalf("falló el caso feliz: %v", err)
	}
	if pedidos.Load() != 1 {
		t.Errorf("pidió %d veces algo que ya estaba listo en la primera", pedidos.Load())
	}
	if tardo := time.Since(arranque); tardo > 5*time.Second {
		t.Errorf("el caso feliz tardó %s: está durmiendo antes de preguntar", tardo)
	}
}

// El presupuesto tiene que cubrir el peor caso realista del otro lado —el
// cold-start de Notary (min_machines_running=0) más las N preparaciones de una
// tanda— y quedar debajo de lo que vive la sesión del servidor: esperar más que
// eso es esperar a algo que ya no existe. Fueron 10 s durante un rato, que es
// menos que un cold-start solo, y el funcionario se comía el timeout DESPUÉS de
// haber puesto el PIN.
func TestElPresupuestoDePollingCubreElColdStart(t *testing.T) {
	if PresupuestoPolling < 60*time.Second {
		t.Errorf("el presupuesto es %s: no alcanza para un cold-start de Notary",
			PresupuestoPolling)
	}
	if PresupuestoPolling >= SesionServidorTTL {
		t.Errorf("el presupuesto (%s) llega o pasa el TTL de la sesión del servidor (%s): "+
			"se estaría esperando a una sesión ya vencida",
			PresupuestoPolling, SesionServidorTTL)
	}
}

// El backoff existe para no martillar al servidor durante dos minutos, pero no
// puede crecer sin techo: cuando el servidor termina, el próximo poll no puede
// estar a una eternidad de distancia.
func TestLaEsperaCreceHastaElTechoYSeQuedaAhi(t *testing.T) {
	const techo = 2 * time.Second

	espera := EsperaPollingInicial
	primera := siguienteEspera(espera, techo)
	if primera <= espera {
		t.Fatalf("la espera no crece: %s → %s", espera, primera)
	}

	espera = primera
	for i := 0; i < 20; i++ {
		proxima := siguienteEspera(espera, techo)
		if proxima < espera {
			t.Fatalf("la espera se achicó: %s → %s", espera, proxima)
		}
		if proxima > techo {
			t.Fatalf("la espera se pasó del techo: %s > %s", proxima, techo)
		}
		espera = proxima
	}
	if espera != techo {
		t.Errorf("después de 20 pasos la espera es %s y el techo es %s", espera, techo)
	}
}

// El polling va por op=get contra el retriever, con el id que corresponde. Si
// se mandara otra op o el id equivocado, el servidor contestaría 404 y la firma
// moriría después del PIN.
func TestElPollingUsaOpGetConSuId(t *testing.T) {
	var op, id string
	lista := []DigestItem{{ID: "SES9", DigestB64: digestDe(t, TamanoDigestSHA256)}}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		op, id = r.FormValue("op"), r.FormValue("id")
		fmt.Fprint(w, digestsB64(t, lista))
	}))
	defer s.Close()

	if _, err := esperarDigests(s.URL, "FILE123", time.Second, time.Millisecond, 2*time.Millisecond); err != nil {
		t.Fatalf("falló: %v", err)
	}
	if op != "get" {
		t.Errorf("polleó con op=%q", op)
	}
	if id != "FILE123" {
		t.Errorf("polleó el id %q y era FILE123", id)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Envelope y manifiesto: reconocer al servidor viejo
// ─────────────────────────────────────────────────────────────────────────────

func envelopeConEntradas(t *testing.T, version string, kv map[string]string) *Envelope {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, `<op v="%s">`, version)
	for k, v := range kv {
		fmt.Fprintf(&b, `<e k="%s" v="%s"/>`, k, v)
	}
	b.WriteString(`</op>`)

	var env Envelope
	if err := xml.Unmarshal([]byte(b.String()), &env); err != nil {
		t.Fatalf("el XML del caso de prueba no parsea: %v", err)
	}
	return &env
}

// Desde 1.4.0 el firmador no sabe firmar un PDF: el código que lo hacía se
// borró. Un envelope con `dat` es un servidor que quedó atrás, y hay que
// decirlo con todas las letras en vez de intentar firmar y fallar raro.
func TestUnEnvelopeConPDFEsUnServidorViejo(t *testing.T) {
	env := envelopeConEntradas(t, "1_0", map[string]string{"dat": "JVBERi0xLjQK"})

	err := env.ValidarV2()
	if !errors.Is(err, ErrServidorViejo) {
		t.Fatalf("no reconoció al servidor viejo: %v", err)
	}
	if !strings.Contains(err.Error(), "soporte") {
		t.Errorf("el error no le dice al funcionario qué hacer: %v", err)
	}
}

func TestElEnvelopeNuevoPasa(t *testing.T) {
	env := envelopeConEntradas(t, "2", map[string]string{"mode": "digest", "op": "sign"})

	if err := env.ValidarV2(); err != nil {
		t.Fatalf("rechazó un envelope legítimo del protocolo nuevo: %v", err)
	}
}

func TestUnEnvelopeSinModoNoSeFirma(t *testing.T) {
	env := envelopeConEntradas(t, "2", map[string]string{"op": "sign"})

	if err := env.ValidarV2(); err == nil {
		t.Fatal("aceptó un envelope que no declara mode=digest")
	}
}

// En la tanda el manifiesto es la ÚNICA señal de qué protocolo habla el
// servidor: ya no se baja un envelope por documento. Sin este chequeo el
// desfasaje aparecería recién en el polling, después del PIN.
func TestElManifiestoViejoSeRechaza(t *testing.T) {
	viejo := &Manifest{Version: "1_1"}

	if err := viejo.ValidarV2(); !errors.Is(err, ErrServidorViejo) {
		t.Fatalf("aceptó un manifiesto del protocolo viejo: %v", err)
	}
	if err := (&Manifest{Version: ManifestVersionDigest}).ValidarV2(); err != nil {
		t.Errorf("rechazó el manifiesto nuevo: %v", err)
	}
}
