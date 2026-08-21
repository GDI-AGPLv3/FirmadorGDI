// Package storage implementa el cliente HTTP del protocolo @firma storage/retriever.
// Protocolo: POST application/x-www-form-urlencoded con op=put|get.
package storage

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Put sube datos al storage. Devuelve error si la respuesta no es "OK".
func Put(endpoint, id, dat string) error {
	resp, err := httpClient.PostForm(endpoint, url.Values{
		"op": {"put"}, "v": {"1_0"}, "id": {id}, "dat": {dat},
	})
	if err != nil {
		return fmt.Errorf("PUT %s: %w", id, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("PUT %s: status=%d body=%q", id, resp.StatusCode, body)
	}
	return nil
}

// Get recupera datos del storage. Devuelve el body tal cual.
func Get(endpoint, id string) (string, error) {
	resp, err := httpClient.PostForm(endpoint, url.Values{
		"op": {"get"}, "v": {"1_0"}, "id": {id},
	})
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("GET %s: no encontrado (sesión expiró o id inválido)", id)
	}
	body, err := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body)), err
}

// Envelope es el XML que el backend pone en storage para AutoFirmaGDI.
type Envelope struct {
	XMLName xml.Name       `xml:"op"`
	Entries []EnvelopeEntry `xml:"e"`
}

type EnvelopeEntry struct {
	K string `xml:"k,attr"`
	V string `xml:"v,attr"`
}

// FetchEnvelope obtiene el XML del retriever, decodea base64 y lo parsea.
func FetchEnvelope(rtServlet, fileID string) (*Envelope, error) {
	raw, err := Get(rtServlet, fileID)
	if err != nil {
		return nil, err
	}

	// El servidor devuelve el XML en base64 (requerimiento del protocolo @firma).
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("el retriever no devolvió base64 válido: %w", err)
	}

	var env Envelope
	if err := xml.Unmarshal(decoded, &env); err != nil {
		return nil, fmt.Errorf("XML malformado en el envelope: %w", err)
	}
	return &env, nil
}

// Get devuelve el valor de una entrada del envelope por clave, URL-unescapeado.
func (e *Envelope) Get(key string) (string, bool) {
	for _, entry := range e.Entries {
		if entry.K == key {
			v, err := url.QueryUnescape(entry.V)
			if err != nil {
				return entry.V, true
			}
			return v, true
		}
	}
	return "", false
}

// PostResult postea el resultado firmado al stservlet.
// El formato es: base64url-sin-padding(cert_DER + signed_PDF).
func PostResult(stServlet, sessionID string, certDER, signedPDF []byte) error {
	blob := append(certDER, signedPDF...)
	encoded := base64.RawURLEncoding.EncodeToString(blob)
	return Put(stServlet, sessionID, encoded)
}

// PostCancel notifica al backend que el usuario canceló.
func PostCancel(stServlet, sessionID string) error {
	return Put(stServlet, sessionID, "CANCEL")
}

// ─────────────────────────────────────────────────────────────────────────────
// GDI-167 — firma en tanda
// ─────────────────────────────────────────────────────────────────────────────

// Manifest es la lista de documentos que el backend dejó para firmar de una vez.
//
//	<batch v="1_1" n="3"><d fileid="DATA…" id="SES…"/>…</batch>
//
// No trae los PDF: cada uno se baja después con FetchEnvelope, igual que en la
// firma de a una. Meter los N PDF en un solo XML habría reventado por tamaño y
// habría obligado a reescribir el envelope que ya funciona.
type Manifest struct {
	XMLName xml.Name       `xml:"batch"`
	Version string         `xml:"v,attr"`
	Count   int            `xml:"n,attr"`
	Items   []ManifestItem `xml:"d"`
}

// ManifestItem es un documento de la tanda: dónde está su PDF y a qué sesión
// hay que devolverle la firma.
type ManifestItem struct {
	FileID    string `xml:"fileid,attr"`
	SessionID string `xml:"id,attr"`
}

// FetchManifest baja la lista de la tanda. Mismo camino que FetchEnvelope: el
// servidor la devuelve en base64 porque empieza con "<".
func FetchManifest(rtServlet, manifestID string) (*Manifest, error) {
	raw, err := Get(rtServlet, manifestID)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("el retriever no devolvió base64 válido: %w", err)
	}

	var m Manifest
	if err := xml.Unmarshal(decoded, &m); err != nil {
		return nil, fmt.Errorf("XML malformado en el manifiesto: %w", err)
	}
	if len(m.Items) == 0 {
		return nil, fmt.Errorf("el manifiesto no trae ningún documento")
	}
	if m.Count != 0 && m.Count != len(m.Items) {
		// Si el manifiesto dice 5 y trae 3, algo se cortó en el camino. Firmar
		// 3 creyendo que son 5 es justo lo que la tanda no puede hacer.
		return nil, fmt.Errorf(
			"el manifiesto dice %d documentos pero trae %d", m.Count, len(m.Items))
	}
	return &m, nil
}

// PostBatchStatus le avisa al backend cómo terminó la tanda, bajo el id del
// lote. Es una red por si se pierde alguno de los avisos individuales: el
// frontend puede cerrar igual sabiendo qué pasó.
func PostBatchStatus(stServlet, batchID, estado string) error {
	return Put(stServlet, batchID, estado)
}
