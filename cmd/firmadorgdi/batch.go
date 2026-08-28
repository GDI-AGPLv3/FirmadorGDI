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
	"fmt"
	"log"

	"github.com/gdi-latam/firmadorgdi/internal/pkcs11"
	"github.com/gdi-latam/firmadorgdi/internal/storage"
	"github.com/gdi-latam/firmadorgdi/internal/ui"
	"github.com/gdi-latam/firmadorgdi/internal/uri"
	"github.com/gdi-latam/firmadorgdi/internal/version"
)

// Estados que se le reportan al backend bajo el id de la tanda.
//
// BATCH_OK ya no existe: en el protocolo de GDI-405 el mensaje SIGS: va a ESA
// MISMA key, así que mandar un estado después lo pisaría. El SIGS: es el cierre
// de la tanda. Los estados de fracaso siguen, porque en esos casos no hay SIGS
// que mandar.
const (
	batchCancel   = "BATCH_CANCEL"
	batchFailed   = "BATCH_FAILED"
	maxPINRetries = 3
)

func handleBatch(params *uri.Params) error {
	log.Printf("tanda: manifiesto=%s id=%s", params.Manifest, params.SessionID)

	// 1. Bajar la lista de lo que hay que firmar.
	//
	// Esto es lo único que se hace antes del PIN, y es a propósito: el diálogo
	// tiene que decir CUÁNTOS documentos se van a firmar (condición D1-bis), y
	// ese número sale del manifiesto. Son unos bytes de XML: los PDF ya no
	// viajan por acá.
	manifest, err := storage.FetchManifest(params.RtServlet, params.Manifest)
	if err != nil {
		return fmt.Errorf("no se pudo leer la lista de documentos: %w", err)
	}
	if err := manifest.ValidarV2(); err != nil {
		return err
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

	// 3. Un solo diálogo de PIN, que dice cuántos documentos se van a firmar.
	cancelar := func(motivo, estado string) {
		cancelarTandaEntera(params, manifest, motivo, estado)
	}
	if err := pedirPINYLoguear(token, dialogoDeToken(tokenInfo, total), cancelar); err != nil {
		return err
	}
	log.Println("Login OK — firmando la tanda")

	// 4. Un solo certificado para toda la tanda: es lo que le dice al servidor
	// que puede preparar los N documentos.
	if err := storage.PostCert(params.StServlet, params.SessionID, token.CertificateDER()); err != nil {
		cancelarTandaEntera(params, manifest, "no se pudo enviar el certificado", batchFailed)
		return fmt.Errorf("no se pudo enviar el certificado: %w", err)
	}

	// 5. Un solo poll para toda la tanda.
	log.Println("tanda: esperando a que el servidor prepare los documentos...")
	digests, err := storage.EsperarDigests(params.RtServlet, params.Manifest)
	if err != nil {
		cancelarTandaEntera(params, manifest, "el servidor no preparó los documentos", batchFailed)
		return err
	}
	if len(digests) != total {
		cancelarTandaEntera(params, manifest, "faltan digests", batchFailed)
		return fmt.Errorf(
			"el manifiesto pedía firmar %d documentos y el servidor mandó %d digests — "+
				"no se firma una tanda incompleta", total, len(digests))
	}

	// 6. Firmar los N digests con la sesión ya abierta. La barra de progreso
	// mueve por documento aunque ahora sea cuestión de milisegundos: el PDF ya
	// no viaja, lo único que queda es la operación del token.
	progreso := ui.NewProgress(total)
	defer progreso.Close()

	firmas, err := firmarDigests(token, digests, func(n int) { progreso.Update(n, total) })
	if err != nil {
		// ⚠️ Todo o nada: cae la tanda entera, incluidos los que ya se firmaron.
		log.Printf("tanda: FALLÓ: %v", err)
		cancelarTandaEntera(params, manifest, "falló la firma", batchFailed)
		return fmt.Errorf(
			"falló la firma de la tanda (%v).\n\n"+
				"Ninguno de los %d quedó firmado y los números vuelven al "+
				"circuito. Podés volver a intentarlo.", err, total)
	}

	// 7. Devolver las N firmas juntas. Este mensaje cierra la tanda.
	if err := storage.PostFirmas(params.StServlet, params.SessionID, firmas); err != nil {
		cancelarTandaEntera(params, manifest, "no se pudieron devolver las firmas", batchFailed)
		return fmt.Errorf("no se pudieron devolver las firmas: %w", err)
	}
	log.Printf("tanda: %d documentos firmados y enviados", total)

	progreso.Close()
	ui.ShowInfoDialog(version.Producto, fmt.Sprintf("Se firmaron %d documentos.", total))
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
func cancelarTandaEntera(
	params *uri.Params, manifest *storage.Manifest, motivo string, estado string,
) {
	log.Printf("tanda: cancelando las %d sesiones (%s)", len(manifest.Items), motivo)
	for _, item := range manifest.Items {
		if err := storage.PostCancel(params.StServlet, item.SessionID); err != nil {
			log.Printf("tanda: no se pudo cancelar %s: %v", item.SessionID, err)
		}
	}
	_ = storage.PostBatchStatus(params.StServlet, params.SessionID, estado)
}
