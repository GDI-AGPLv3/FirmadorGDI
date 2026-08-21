package main

// Firma en tanda: varios documentos, un solo PIN (GDI-167).
//
// La ganancia no es cosmética: el PIN es del TOKEN, no del documento. Una vez
// abierta la sesión PKCS#11, firmar 1 o 5 PDFs cuesta casi lo mismo — la clave
// privada de estos tokens no exige re-autenticar por firma (verificado con el
// ePass2003 real, prueba A7 del 11/08/2026). Hoy, en cambio, un Secretario que
// firma 15 resoluciones escribe el PIN 15 veces.
//
// ⚠️ TODO O NADA. Si un documento falla, se cancela LA TANDA ENTERA: los que ya
// se firmaron, el que falló y los que faltaban. No se sigue con el resto.
//
// La razón es de numeración, no de prolijidad: firmando de a uno, el número que
// se libera por un fallo es siempre el último entregado, así que nunca queda un
// hueco en el medio. Una tanda parcial rompería esa propiedad por primera vez
// —"se firmaron el 40, 41, 43 y 44, falta el 42"— y para un cuerpo de
// resoluciones eso es inaceptable. Con todo o nada, los números cancelados son
// los N últimos, consecutivos, y la numeración queda como si la tanda nunca
// hubiera existido.

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gdi-latam/firmadorgdi/internal/pkcs11"
	"github.com/gdi-latam/firmadorgdi/internal/signing"
	"github.com/gdi-latam/firmadorgdi/internal/storage"
	"github.com/gdi-latam/firmadorgdi/internal/ui"
	"github.com/gdi-latam/firmadorgdi/internal/uri"
)

// Estados que se le reportan al backend bajo el id de la tanda.
const (
	batchOK       = "BATCH_OK"
	batchCancel   = "BATCH_CANCEL"
	batchFailed   = "BATCH_FAILED"
	maxPINRetries = 3
)

func handleBatch(params *uri.Params) error {
	log.Printf("tanda: manifiesto=%s id=%s", params.Manifest, params.SessionID)

	// 1. Bajar la lista de lo que hay que firmar.
	manifest, err := storage.FetchManifest(params.RtServlet, params.Manifest)
	if err != nil {
		return fmt.Errorf("no se pudo leer la lista de documentos: %w", err)
	}
	total := len(manifest.Items)
	log.Printf("tanda: %d documentos", total)

	// 2. Abrir el token UNA vez para toda la tanda.
	token, tokenInfo, err := pkcs11.Open("")
	if err != nil {
		return fmt.Errorf("token no encontrado: %w", err)
	}
	defer token.Close()
	log.Printf("Token detectado: %s (%s)", tokenInfo.Label, tokenInfo.Manufacturer)

	// 3. Un solo diálogo de PIN, que dice CUÁNTOS documentos se van a firmar.
	//
	// Eso último no es un detalle de UI: es la condición D1-bis de la decisión
	// que habilitó esta feature. Autorizar una tanda sin saber cuántos
	// documentos incluye no es autorizar nada.
	dlgInfo := ui.TokenInfo{
		Label:        tokenInfo.Label,
		Manufacturer: tokenInfo.Manufacturer,
		Subject:      tokenInfo.Subject,
		SerialNumber: tokenInfo.SerialNumber,
		ValidUntil:   tokenInfo.ValidUntil,
		BatchCount:   total,
	}

	if err := loginConReintentos(token, dlgInfo, params, manifest); err != nil {
		return err
	}
	log.Println("Login OK — firmando la tanda")

	// 4. Firmar de a uno, en el orden en que vinieron.
	cert := token.Certificate()
	certDER := token.CertificateDER()

	progreso := ui.NewProgress(total)
	defer progreso.Close()

	for i, item := range manifest.Items {
		progreso.Update(i+1, total)
		log.Printf("tanda: firmando %d de %d (session=%s)", i+1, total, item.SessionID)

		if err := firmarUno(params, item, cert, certDER, token); err != nil {
			// ⚠️ Acá se corta. No se sigue con los que faltan.
			log.Printf("tanda: FALLÓ el documento %d de %d: %v", i+1, total, err)
			cancelarTandaEntera(params, manifest, fmt.Sprintf("documento %d", i+1))
			return fmt.Errorf(
				"falló el documento %d de %d (%v).\n\n"+
					"Ninguno de los %d quedó firmado y los números vuelven al "+
					"circuito. Podés volver a intentarlo.",
				i+1, total, err, total,
			)
		}
	}

	_ = storage.PostBatchStatus(params.StServlet, params.SessionID, batchOK)
	log.Printf("tanda: %d documentos firmados y enviados", total)
	return nil
}

// loginConReintentos pide el PIN hasta maxPINRetries veces. Si el usuario
// cancela o se acaban los intentos, cae la tanda entera — en ese momento no se
// firmó nada todavía, así que solo hay que devolver los números.
func loginConReintentos(
	token *pkcs11.Token,
	dlgInfo ui.TokenInfo,
	params *uri.Params,
	manifest *storage.Manifest,
) error {
	for intento := 1; intento <= maxPINRetries; intento++ {
		result, dlgErr := ui.ShowPINDialog(dlgInfo)
		if errors.Is(dlgErr, ui.ErrCancelled) {
			cancelarTandaEntera(params, manifest, "cancelado en el PIN")
			return fmt.Errorf("el usuario canceló la firma")
		}
		if dlgErr != nil {
			cancelarTandaEntera(params, manifest, "error del diálogo")
			return fmt.Errorf("no se pudo mostrar el diálogo de PIN: %w", dlgErr)
		}
		if result.PIN == "" {
			cancelarTandaEntera(params, manifest, "PIN vacío")
			return fmt.Errorf("PIN vacío recibido del diálogo")
		}

		if loginErr := token.Login(result.PIN); loginErr != nil {
			log.Printf("Login intento %d: %v", intento, loginErr)
			if errors.Is(loginErr, pkcs11.ErrTokenLocked) {
				cancelarTandaEntera(params, manifest, "token bloqueado")
				return fmt.Errorf("token bloqueado — demasiados PINs incorrectos")
			}
			dlgInfo.WrongPIN = true
			continue
		}
		return nil
	}

	cancelarTandaEntera(params, manifest, "máximo de intentos")
	return fmt.Errorf("máximo de intentos alcanzado")
}

// firmarUno hace, para un documento de la tanda, exactamente lo mismo que la
// firma de a una: bajar su PDF, armar la apariencia, firmar y devolver. El
// token ya está abierto y logueado — eso es todo lo que la tanda ahorra.
func firmarUno(
	params *uri.Params,
	item storage.ManifestItem,
	cert *x509.Certificate,
	certDER []byte,
	token *pkcs11.Token,
) error {
	env, err := storage.FetchEnvelope(params.RtServlet, item.FileID)
	if err != nil {
		return fmt.Errorf("no se pudo bajar el documento: %w", err)
	}

	pdfB64, ok := env.Get("dat")
	if !ok {
		return fmt.Errorf("el documento vino sin contenido")
	}
	pdfBytes, err := base64.StdEncoding.DecodeString(pdfB64)
	if err != nil {
		return fmt.Errorf("el documento vino mal codificado: %w", err)
	}

	var app *signing.Appearance
	if propsB64, ok := env.Get("properties"); ok && propsB64 != "" {
		app, err = signing.AppearanceFromProperties(
			propsB64, cert.Subject.CommonName, cert.Subject.SerialNumber)
		if err != nil {
			log.Println("WARN: properties inválidas, usando defaults:", err)
		}
	}
	if app == nil {
		app = &signing.Appearance{
			Page: 1, LowerLeftX: 365, LowerLeftY: 30, UpperRightX: 565, UpperRightY: 90, //nolint
			SignerName: cert.Subject.CommonName,
			SerialNum:  cert.Subject.SerialNumber,
			Reason:     "Firma digital",
			SignedAt:   time.Now().Local(),
		}
	}

	signedPDF, err := signing.SignPDF(pdfBytes, cert, token.Signer(), *app)
	if err != nil {
		return fmt.Errorf("no se pudo firmar: %w", err)
	}

	if err := storage.PostResult(params.StServlet, item.SessionID, certDER, signedPDF); err != nil {
		return fmt.Errorf("no se pudo devolver la firma: %w", err)
	}
	return nil
}

// cancelarTandaEntera avisa que caen TODAS las sesiones: las ya firmadas, la
// que falló y las que faltaban.
//
// Se cancelan también las ya firmadas a propósito. Del lado del servidor esos
// PDF están esperando en un lugar borrable justamente para esto: mientras la
// tanda no cierre entera, nada se promueve al archivo definitivo, que es
// inmutable. Es lo que hace posible el todo o nada.
//
// Todo best-effort: si algún aviso no llega, el servidor la deja caer sola por
// vencimiento. Un aviso perdido no puede impedir los demás.
func cancelarTandaEntera(params *uri.Params, manifest *storage.Manifest, motivo string) {
	log.Printf("tanda: cancelando las %d sesiones (%s)", len(manifest.Items), motivo)
	for _, item := range manifest.Items {
		if err := storage.PostCancel(params.StServlet, item.SessionID); err != nil {
			log.Printf("tanda: no se pudo cancelar %s: %v", item.SessionID, err)
		}
	}
	estado := batchFailed
	if motivo == "cancelado en el PIN" {
		estado = batchCancel
	}
	_ = storage.PostBatchStatus(params.StServlet, params.SessionID, estado)
}
