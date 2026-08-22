package storage

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gdi-latam/firmadorgdi/internal/version"
)

// servidorQueDevuelve levanta un retriever de mentira que contesta siempre lo
// mismo, ya codificado como lo hace el backend real (base64, porque el XML
// empieza con "<").
func servidorQueDevuelve(t *testing.T, xml string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(xml)))
	}))
	t.Cleanup(s.Close)
	return s
}

func manifiestoCon(n int, items int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><batch v="1_1" n="%d">`, n)
	for i := 0; i < items; i++ {
		fmt.Fprintf(&b, `<d fileid="F%d" id="S%d"/>`, i, i)
	}
	b.WriteString(`</batch>`)
	return b.String()
}

// Una tanda son 5 documentos. Un manifiesto que pida un millón no es un caso de
// uso: es un servidor hostil, o uno propio que se rompió. Sin este freno el
// número llega al diálogo y el funcionario ve "vas a firmar 1000000
// documentos" — y si acepta, el programa entra en un loop del que no vuelve.
func TestElManifiestoNoPuedePedirMasDeLoPermitido(t *testing.T) {
	// Uno por encima del tope alcanza para probarlo. Generar el millón entero
	// tardaba 15 segundos en cada corrida y no probaba nada más.
	demas := MaxDocumentosManifiesto + 1
	s := servidorQueDevuelve(t, manifiestoCon(demas, demas))

	_, err := FetchManifest(s.URL, "MAN123")
	if err == nil {
		t.Fatal("aceptó un manifiesto de un millón de documentos")
	}
	if !strings.Contains(err.Error(), "máximo") {
		t.Errorf("el error no explica que hay un tope: %v", err)
	}
}

// El n declarado se chequea aparte de los items reales: es el número que se le
// muestra al funcionario en el diálogo, así que un n gigante con tres items
// tiene que rebotar aunque los items entren holgados.
func TestElNDeclaradoTambienTieneTope(t *testing.T) {
	s := servidorQueDevuelve(t, manifiestoCon(1000000, 3))

	if _, err := FetchManifest(s.URL, "MAN123"); err == nil {
		t.Fatal("aceptó un manifiesto que declara un millón y trae tres")
	}
}

// El caso normal tiene que seguir pasando: cinco documentos son una tanda.
func TestLaTandaNormalPasa(t *testing.T) {
	s := servidorQueDevuelve(t, manifiestoCon(5, 5))

	m, err := FetchManifest(s.URL, "MAN123")
	if err != nil {
		t.Fatalf("rechazó una tanda válida de 5: %v", err)
	}
	if len(m.Items) != 5 {
		t.Errorf("trajo %d documentos y eran 5", len(m.Items))
	}
	if m.Items[0].FileID != "F0" || m.Items[0].SessionID != "S0" {
		t.Errorf("los atributos del manifiesto no mapearon: %+v", m.Items[0])
	}
}

// Sin techo de descarga, un servidor que manda un cuerpo interminable agota la
// memoria del equipo municipal. Se corta y se avisa, en vez de devolver un
// pedazo truncado como si fuera el documento entero.
func TestNoSeBajaMasDeLTecho(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bloque := strings.Repeat("A", 1<<20) // 1 MB
		for i := 0; i < (MaxDescargaBytes>>20)+2; i++ {
			if _, err := w.Write([]byte(bloque)); err != nil {
				return // el cliente cortó: es justamente lo que se espera
			}
		}
	}))
	defer s.Close()

	_, err := Get(s.URL, "X")
	if err == nil {
		t.Fatal("se bajó un cuerpo más grande que el techo sin protestar")
	}
	if !strings.Contains(err.Error(), "MB") {
		t.Errorf("el error no dice que se pasó de tamaño: %v", err)
	}
}

// Sin esto no hay forma de saber qué versión corre un municipio: no hay
// auto-update ni telemetría, y el binario solo escribía su versión en el log de
// su propia máquina. El servidor la usa para avisarle al funcionario que tiene
// una versión vieja, que es todo el mecanismo de actualización que existe.
func TestCadaPedidoDiceQueVersionEs(t *testing.T) {
	var recibidoHeader, recibidoUA string

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recibidoHeader = r.Header.Get(HeaderVersion)
		recibidoUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, "OK")
	}))
	defer s.Close()

	if err := Put(s.URL, "SES1", "datos"); err != nil {
		t.Fatalf("el PUT falló: %v", err)
	}
	if recibidoHeader != version.Version {
		t.Errorf("el header dijo %q y la versión es %q", recibidoHeader, version.Version)
	}
	if !strings.Contains(recibidoUA, version.Version) {
		t.Errorf("el User-Agent no lleva la versión: %q", recibidoUA)
	}

	// Y también en el GET, que es el primer contacto con el servidor: es el que
	// permite avisar ANTES de que el funcionario ponga el PIN.
	recibidoHeader = ""
	_, _ = Get(s.URL, "SES1")
	if recibidoHeader != version.Version {
		t.Errorf("el GET no mandó la versión: %q", recibidoHeader)
	}
}
