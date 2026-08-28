// FirmadorGDI — cliente de firma digital con token físico para GDI Latam.
// Drop-in replacement de AutoFirma España para municipios LATAM.
//
// Modo normal (lanzado por Chrome vía URI handler):
//
//	firmadorgdi.exe "gdifirma://sign?ver=1_0&fileid=X&rtservlet=Y&stservlet=Z&id=W&keystore=PKCS11"
//
// Modo instalación (registrar URI scheme, sin admin):
//
//	firmadorgdi.exe --register
//
// Ver qué versión está instalada:
//
//	firmadorgdi.exe --version
package main

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gdi-latam/firmadorgdi/internal/pkcs11"
	"github.com/gdi-latam/firmadorgdi/internal/storage"
	"github.com/gdi-latam/firmadorgdi/internal/ui"
	"github.com/gdi-latam/firmadorgdi/internal/uri"
	"github.com/gdi-latam/firmadorgdi/internal/version"
	"golang.org/x/sys/windows/registry"
)

func main() {
	setupLog()

	if len(os.Args) < 2 {
		ui.ShowInfoDialog(version.Producto, fmt.Sprintf(
			"FirmadorGDI %s está instalado y listo.\n\nPara firmar documentos, ingresá a tu sistema desde el navegador y hacé clic en \"Firmar\".",
			version.Version,
		))
		os.Exit(0)
	}

	arg := os.Args[1]

	switch {
	// GDI-341: sin esto no había forma de saber qué versión tiene instalada un
	// municipio. Va a stdout —no a un diálogo— para poder leerlo por consola o
	// desde un script de soporte.
	case arg == "--version" || arg == "-v":
		// engancharConsola() PRIMERO. El binario se compila con -H windowsgui
		// —para que Chrome no abra una ventana negra en cada firma— y entonces
		// Windows no le da consola: este Printf escribiría en un handle vacío.
		//
		// La función existía desde el commit que dio esto por resuelto, pero
		// nunca se la llamaba desde ningún lado, así que `--version` seguía sin
		// imprimir una sola línea. Santiago lo reportó y se atribuyó al shell.
		if !engancharConsola() {
			// Doble clic: no hay consola de nadie ni redirección. El único
			// lugar donde se puede mostrar algo es un diálogo.
			ui.ShowInfoDialog(version.Producto,
				fmt.Sprintf("%s %s", version.Producto, version.Version))
			os.Exit(0)
		}
		fmt.Printf("%s %s\n", version.Producto, version.Version)
		os.Exit(0)

	case arg == "--register":
		if err := registerURIScheme(); err != nil {
			log.Fatal("ERROR registrando scheme:", err)
		}
		ui.ShowInfoDialog("FirmadorGDI instalado", "gdifirma:// registrado correctamente.\nYa podés usar FirmadorGDI desde Chrome.")

	case strings.HasPrefix(arg, uri.Scheme+"://"):
		// GDI-167: el mismo case atiende las dos operaciones. Se bifurca por el
		// HOST de la URI (sign|batch), no por el `default` de más abajo: una URI
		// gdifirma://batch entra igual por acá, así que cambiar el mensaje del
		// default no serviría de nada.
		if err := handleURI(arg); err != nil {
			log.Println("ERROR:", err)
			ui.ShowErrorDialog("Error al firmar", err.Error())
		}

	default:
		ui.ShowErrorDialog("FirmadorGDI — Error", fmt.Sprintf("Argumento desconocido: %q", arg))
		os.Exit(1)
	}
}

// handleURI parsea y despacha: un documento o una tanda.
func handleURI(rawURI string) error {
	log.Println("URI recibida:", rawURI)

	params, err := uri.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("URI inválida: %w", err)
	}

	if params.Op == uri.OpBatch {
		return handleBatch(params)
	}
	return handleSign(params)
}

// handleSign firma UN documento con el protocolo de GDI-405: el PDF no viaja.
//
// El orden es el que cambió de raíz respecto de 1.3.1. Antes se bajaba el PDF
// —hasta 50 MB— y recién después se abría el token; si el funcionario cancelaba
// el PIN, esa descarga había sido para nada. Ahora el PIN va PRIMERO: sin token
// abierto no hay certificado, y sin certificado el servidor ni siquiera puede
// empezar a preparar el documento.
func handleSign(params *uri.Params) error {
	log.Printf("fileid=%s session=%s keystore=%s", params.FileID, params.SessionID, params.Keystore)

	// 1. Token y PIN, antes de cualquier ida y vuelta con el servidor.
	token, tokenInfo, err := pkcs11.Open("")
	if err != nil {
		return fmt.Errorf("token no encontrado: %w", err)
	}
	defer token.Close()
	log.Printf("Token detectado: %s (%s)", tokenInfo.Label, tokenInfo.Manufacturer)

	cancelar := func(string, string) {
		_ = storage.PostCancel(params.StServlet, params.SessionID)
	}
	if err := pedirPINYLoguear(token, dialogoDeToken(tokenInfo, 0), cancelar); err != nil {
		return err
	}
	log.Println("Login OK")

	// 2. Envelope: solo para confirmar que del otro lado hay un servidor que
	// habla el protocolo nuevo. Ya no trae documento.
	env, err := storage.FetchEnvelope(params.RtServlet, params.FileID)
	if err != nil {
		cancelar("", "")
		return fmt.Errorf("no se pudo consultar el documento: %w", err)
	}
	if err := env.ValidarV2(); err != nil {
		cancelar("", "")
		return err
	}

	// 3. Mandar el certificado: es lo que dispara la preparación del lado del
	// servidor (estampa el sello con estos datos y arma el CMS).
	if err := storage.PostCert(params.StServlet, params.SessionID, token.CertificateDER()); err != nil {
		cancelar("", "")
		return fmt.Errorf("no se pudo enviar el certificado: %w", err)
	}

	// 4. Esperar los digests.
	log.Println("Esperando a que el servidor prepare el documento...")
	digests, err := storage.EsperarDigests(params.RtServlet, params.FileID)
	if err != nil {
		cancelar("", "")
		return err
	}

	// 5. Firmar con el token.
	firmas, err := firmarDigests(token, digests, nil)
	if err != nil {
		cancelar("", "")
		return err
	}

	// 6. Devolver las firmas.
	if err := storage.PostFirmas(params.StServlet, params.SessionID, firmas); err != nil {
		return fmt.Errorf("no se pudo devolver la firma: %w", err)
	}
	log.Println("Firma enviada al backend. Cerrando.")

	ui.ShowInfoDialog(version.Producto, "El documento quedó firmado.")
	return nil
}

// firmarDigests le pasa al token cada digest de la tanda y junta las firmas.
//
// avance, si no es nil, se llama con el número de documento que se está
// firmando: es lo que mueve la barra de progreso de la tanda.
func firmarDigests(
	token *pkcs11.Token, digests []storage.DigestItem, avance func(n int),
) ([]storage.FirmaItem, error) {
	signer := token.Signer()
	firmas := make([]storage.FirmaItem, 0, len(digests))

	for i, d := range digests {
		if avance != nil {
			avance(i + 1)
		}
		// Valida que sean 32 bytes. El token firma a ciegas lo que se le pase:
		// si acá entrara otra cosa, saldría una firma válida sobre algo que no
		// es el documento que el funcionario autorizó.
		digest, err := d.Digest()
		if err != nil {
			return nil, err
		}
		sig, err := signer.Sign(nil, digest, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("el token no pudo firmar el documento %s: %w", d.ID, err)
		}
		firmas = append(firmas, storage.FirmaItem{
			ID:     d.ID,
			SigB64: base64.StdEncoding.EncodeToString(sig),
		})
	}
	log.Printf("%d documento(s) firmado(s) por el token", len(firmas))
	return firmas, nil
}

// dialogoDeToken arma lo que ve el funcionario. batchCount en 0 o 1 es la firma
// de a una y el cartel no cambia.
func dialogoDeToken(info *pkcs11.TokenInfo, batchCount int) ui.TokenInfo {
	return ui.TokenInfo{
		Label:        info.Label,
		Manufacturer: info.Manufacturer,
		Subject:      info.Subject,
		SerialNumber: info.SerialNumber,
		ValidUntil:   info.ValidUntil,
		BatchCount:   batchCount,
	}
}

// pedirPINYLoguear muestra el diálogo del PIN hasta maxPINRetries veces.
//
// cancelar recibe el motivo y el estado que hay que reportarle al servidor; qué
// se hace con eso depende de si es una firma sola (cancelar la sesión) o una
// tanda (cancelarlas todas).
func pedirPINYLoguear(
	token *pkcs11.Token, dlgInfo ui.TokenInfo, cancelar func(motivo, estado string),
) error {
	for intento := 1; intento <= maxPINRetries; intento++ {
		result, dlgErr := ui.ShowPINDialog(dlgInfo)
		if errors.Is(dlgErr, ui.ErrCancelled) {
			cancelar("cancelado en el PIN", batchCancel)
			return fmt.Errorf("el usuario canceló la firma")
		}
		if dlgErr != nil {
			cancelar("error del diálogo", batchFailed)
			return fmt.Errorf("no se pudo mostrar el diálogo de PIN: %w", dlgErr)
		}
		if result.PIN == "" {
			cancelar("PIN vacío", batchFailed)
			return fmt.Errorf("PIN vacío recibido del diálogo")
		}

		if loginErr := token.Login(result.PIN); loginErr != nil {
			log.Printf("Login intento %d: %v", intento, loginErr)
			if errors.Is(loginErr, pkcs11.ErrTokenLocked) {
				cancelar("token bloqueado", batchFailed)
				return fmt.Errorf("token bloqueado — demasiados PINs incorrectos")
			}
			dlgInfo.WrongPIN = true
			continue
		}
		return nil
	}

	cancelar("máximo de intentos", batchCancel)
	return fmt.Errorf("máximo de intentos alcanzado")
}

func registerURIScheme() error {
	exePath, _ := os.Executable()
	exePath, _ = filepath.Abs(exePath)
	base := `Software\Classes\gdifirma`
	for path, val := range map[string]string{
		base:                         "URL:GDI Firma Protocol",
		base + `\URL Protocol`:       "",
		base + `\shell\open\command`: fmt.Sprintf(`"%s" "%%1"`, exePath),
	} {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if err != nil {
			return err
		}
		k.SetStringValue("", val)
		k.Close()
	}
	return nil
}

func setupLog() {
	logPath := filepath.Join(os.TempDir(), "firmadorgdi.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime)
	// GDI-341: la primera línea de cada corrida dice la versión. Cuando alguien
	// manda este log para reportar un problema, deja de hacer falta preguntarle
	// qué versión tiene.
	log.Printf("=== %s %s ===", version.Producto, version.Version)
}
