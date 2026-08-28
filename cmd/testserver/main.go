// testserver — servidor local que simula rtservlet + stservlet del protocolo
// nuevo (GDI-405: al token viaja el digest).
//
// Uso: go run ./cmd/testserver  → imprime la URL gdifirma:// para abrir en Chrome.
//
// Es el único banco de pruebas con token real que existe. No prepara un PDF de
// verdad —eso lo hace Notary del otro lado—: manda un digest de 32 bytes
// inventado y, cuando vuelve la firma, la VERIFICA con la clave pública del
// certificado que mandó el token. Si eso da bien, el circuito completo anduvo:
// el token firmó exactamente los bytes que se le pidieron.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	port      = "8765"
	fileID    = "TESTFILE001"
	sessionID = "TESTSESSION001"

	// Cuántos polls se contestan con PENDING antes de largar los digests. Sirve
	// para ver que el cliente realmente espera en vez de rendirse al primer
	// intento.
	pollsPendientes = 2
)

type envelope struct {
	XMLName xml.Name        `xml:"op"`
	Version string          `xml:"v,attr"`
	Entries []envelopeEntry `xml:"e"`
}

type envelopeEntry struct {
	K string `xml:"k,attr"`
	V string `xml:"v,attr"`
}

type digestItem struct {
	ID        string `json:"id"`
	DigestB64 string `json:"digest_b64"`
}

type firmaItem struct {
	ID     string `json:"id"`
	SigB64 string `json:"sig_b64"`
}

// estado es lo que el servidor sabe de la sesión en curso.
type estado struct {
	mu     sync.Mutex
	cert   *x509.Certificate
	digest []byte
	polls  int
}

var st estado

func main() {
	// El "digest a firmar" que en producción sale de pyHanko
	// (sha256 de los SignedAttributes). Acá alcanza con 32 bytes estables.
	suma := sha256.Sum256([]byte("SignedAttributes de prueba — FirmadorGDI"))
	st.digest = suma[:]

	env := envelope{
		Version: "2",
		Entries: []envelopeEntry{
			{K: "mode", V: "digest"},
			{K: "op", V: "sign"},
			{K: "format", V: "PADES"},
		},
	}
	envXML, _ := xml.Marshal(env)
	envB64 := base64.StdEncoding.EncodeToString(envXML)

	// rtservlet: primero devuelve el envelope; una vez que llegó el
	// certificado, pasa a contestar el polling (PENDING → DIGESTS).
	http.HandleFunc("/rt", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		op, id := r.FormValue("op"), r.FormValue("id")
		log.Printf("rtservlet: op=%s id=%s", op, id)
		if op != "get" {
			http.Error(w, "op desconocida", 400)
			return
		}

		st.mu.Lock()
		defer st.mu.Unlock()

		if st.cert == nil {
			fmt.Fprint(w, envB64)
			return
		}
		st.polls++
		if st.polls <= pollsPendientes {
			fmt.Fprint(w, "PENDING")
			return
		}
		lista, _ := json.Marshal([]digestItem{{
			ID:        sessionID,
			DigestB64: base64.StdEncoding.EncodeToString(st.digest),
		}})
		fmt.Fprint(w, "DIGESTS:"+base64.RawURLEncoding.EncodeToString(lista))
	})

	// stservlet: recibe el certificado y después las firmas.
	http.HandleFunc("/st", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		op, id, dat := r.FormValue("op"), r.FormValue("id"), r.FormValue("dat")
		log.Printf("stservlet: op=%s id=%s datLen=%d", op, id, len(dat))
		if op != "put" {
			http.Error(w, "op desconocida", 400)
			return
		}

		switch {
		case dat == "CANCEL" || strings.HasPrefix(dat, "BATCH_"):
			fmt.Printf("\n⚠  La firma no se completó: %s\n", dat)

		case strings.HasPrefix(dat, "CERT:"):
			if err := recibirCert(strings.TrimPrefix(dat, "CERT:")); err != nil {
				log.Printf("cert inválido: %v", err)
				http.Error(w, "cert inválido", 400)
				return
			}

		case strings.HasPrefix(dat, "SIGS:"):
			if err := verificarFirmas(strings.TrimPrefix(dat, "SIGS:")); err != nil {
				fmt.Printf("\n✗  LA FIRMA NO VERIFICA: %v\n", err)
				http.Error(w, "firma inválida", 400)
				return
			}

		default:
			log.Printf("dat desconocido (%d bytes)", len(dat))
			http.Error(w, "dat desconocido", 400)
			return
		}
		fmt.Fprint(w, "OK")
	})

	base := fmt.Sprintf("http://localhost:%s", port)
	gdiURI := fmt.Sprintf(
		"gdifirma://sign?ver=1_0&fileid=%s&rtservlet=%s&stservlet=%s&id=%s&keystore=PKCS11",
		fileID, url.QueryEscape(base+"/rt"), url.QueryEscape(base+"/st"), sessionID,
	)

	fmt.Println("\n─────────────────────────────────────────────────────")
	fmt.Printf("Servidor escuchando en %s (protocolo digest, GDI-405)\n\n", base)
	fmt.Println("Abrí esta URL en Chrome para disparar el firmador:")
	fmt.Printf("\n  %s\n\n", gdiURI)
	fmt.Println("O abrí test.html en Chrome (se genera en el directorio actual).")
	fmt.Println("─────────────────────────────────────────────────────")

	writeTestHTML(gdiURI)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func recibirCert(b64 string) error {
	der, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("base64: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("DER: %w", err)
	}
	st.mu.Lock()
	st.cert = cert
	st.polls = 0
	st.mu.Unlock()

	fmt.Printf("\n✓  Certificado recibido: %s (%d bytes DER)\n",
		cert.Subject.CommonName, len(der))
	return nil
}

// verificarFirmas es el único chequeo que importa: que la firma que devolvió el
// token sea una PKCS#1 v1.5 del digest que se le mandó, con la clave pública
// del certificado que él mismo declaró.
func verificarFirmas(b64 string) error {
	crudo, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("base64: %w", err)
	}
	var firmas []firmaItem
	if err := json.Unmarshal(crudo, &firmas); err != nil {
		return fmt.Errorf("JSON: %w", err)
	}

	st.mu.Lock()
	cert, digest := st.cert, st.digest
	st.mu.Unlock()
	if cert == nil {
		return fmt.Errorf("llegaron firmas sin certificado previo")
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("el certificado no tiene clave RSA")
	}

	for _, f := range firmas {
		sig, err := base64.StdEncoding.DecodeString(f.SigB64)
		if err != nil {
			return fmt.Errorf("firma de %s en base64 inválido: %w", f.ID, err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
			return fmt.Errorf("documento %s: %w", f.ID, err)
		}
		fmt.Printf("\n✓  Firma de %s VERIFICADA (%d bytes) contra el digest enviado\n",
			f.ID, len(sig))
	}
	return nil
}

func writeTestHTML(uri string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Test FirmadorGDI</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #0F172A; color: #F1F5F9;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1E293B; border-radius: 12px; padding: 40px; text-align: center; max-width: 420px; }
    h1 { font-size: 22px; margin-bottom: 8px; }
    p  { color: #94A3B8; font-size: 14px; margin-bottom: 28px; }
    a  { display: inline-block; background: #0EA5E9; color: white; text-decoration: none;
         padding: 12px 32px; border-radius: 8px; font-weight: 600; font-size: 15px; }
    a:hover { background: #0284C7; }
    .note { color: #64748B; font-size: 12px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔐 Test FirmadorGDI</h1>
    <p>Hacé clic para disparar el firmador con un digest de prueba.</p>
    <a href="%s">Firmar digest de prueba</a>
    <p class="note">El resultado se verifica en la consola del servidor: no se genera ningún PDF.</p>
  </div>
</body>
</html>`, uri)

	path, _ := filepath.Abs("test.html")
	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		log.Printf("No se pudo generar test.html: %v", err)
		return
	}
	fmt.Printf("test.html generado en: %s\n", path)
}
