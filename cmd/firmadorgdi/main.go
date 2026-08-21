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
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdi-latam/firmadorgdi/internal/pkcs11"
	"github.com/gdi-latam/firmadorgdi/internal/signing"
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
		fmt.Printf("%s %s\n", version.Producto, version.Version)
		os.Exit(0)

	case arg == "--register":
		if err := registerURIScheme(); err != nil {
			log.Fatal("ERROR registrando scheme:", err)
		}
		ui.ShowInfoDialog("FirmadorGDI instalado", "gdifirma:// registrado correctamente.\nYa podés usar FirmadorGDI desde Chrome.")

	case strings.HasPrefix(arg, uri.Scheme+"://"):
		if err := handleSign(arg); err != nil {
			log.Println("ERROR:", err)
			ui.ShowErrorDialog("Error al firmar", err.Error())
		}

	default:
		ui.ShowErrorDialog("FirmadorGDI — Error", fmt.Sprintf("Argumento desconocido: %q", arg))
		os.Exit(1)
	}
}

func handleSign(rawURI string) error {
	log.Println("URI recibida:", rawURI)

	// 1. Parsear URI.
	params, err := uri.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("URI inválida: %w", err)
	}
	log.Printf("fileid=%s session=%s keystore=%s", params.FileID, params.SessionID, params.Keystore)

	// 2. Buscar el XML envelope en el rtservlet.
	log.Println("Buscando PDF en el backend...")
	env, err := storage.FetchEnvelope(params.RtServlet, params.FileID)
	if err != nil {
		return fmt.Errorf("FetchEnvelope: %w", err)
	}

	pdfB64, ok := env.Get("dat")
	if !ok {
		return fmt.Errorf("el envelope no contiene el PDF (falta 'dat')")
	}
	pdfBytes, err := base64.StdEncoding.DecodeString(pdfB64)
	if err != nil {
		return fmt.Errorf("PDF en base64 inválido: %w", err)
	}
	log.Printf("PDF recibido: %d bytes", len(pdfBytes))

	// 3. Inicializar token.
	token, tokenInfo, err := pkcs11.Open("")
	if err != nil {
		return fmt.Errorf("token no encontrado: %w", err)
	}
	defer token.Close()
	log.Printf("Token detectado: %s (%s)", tokenInfo.Label, tokenInfo.Manufacturer)

	// 4. Diálogo PIN con reintentos (máx. 3).
	const maxAttempts = 3
	dlgInfo := ui.TokenInfo{
		Label:        tokenInfo.Label,
		Manufacturer: tokenInfo.Manufacturer,
		Subject:      tokenInfo.Subject,
		SerialNumber: tokenInfo.SerialNumber,
		ValidUntil:   tokenInfo.ValidUntil,
	}
	var loginOK bool
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, dlgErr := ui.ShowPINDialog(dlgInfo)
		if errors.Is(dlgErr, ui.ErrCancelled) {
			_ = storage.PostCancel(params.StServlet, params.SessionID)
			return fmt.Errorf("el usuario canceló la firma")
		}
		if dlgErr != nil {
			_ = storage.PostCancel(params.StServlet, params.SessionID)
			return fmt.Errorf("no se pudo mostrar el diálogo de PIN: %w", dlgErr)
		}
		if result.PIN == "" {
			_ = storage.PostCancel(params.StServlet, params.SessionID)
			return fmt.Errorf("PIN vacío recibido del diálogo")
		}

		if loginErr := token.Login(result.PIN); loginErr != nil {
			log.Printf("Login intento %d: %v", attempt, loginErr)
			if errors.Is(loginErr, pkcs11.ErrTokenLocked) {
				_ = storage.PostCancel(params.StServlet, params.SessionID)
				return fmt.Errorf("token bloqueado — demasiados PINs incorrectos")
			}
			dlgInfo.WrongPIN = true
			continue
		}
		loginOK = true
		break
	}
	if !loginOK {
		_ = storage.PostCancel(params.StServlet, params.SessionID)
		return fmt.Errorf("máximo de intentos alcanzado")
	}
	log.Println("Login OK")

	// 5. Construir appearance desde properties del envelope.
	cert := token.Certificate()
	var app *signing.Appearance
	if propsB64, ok := env.Get("properties"); ok && propsB64 != "" {
		app, err = signing.AppearanceFromProperties(propsB64, cert.Subject.CommonName, cert.Subject.SerialNumber)
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

	// 6. Firmar el PDF.
	log.Println("Firmando PDF...")
	signedPDF, err := signing.SignPDF(pdfBytes, cert, token.Signer(), *app)
	if err != nil {
		_ = storage.PostCancel(params.StServlet, params.SessionID)
		return fmt.Errorf("SignPDF: %w", err)
	}
	log.Printf("PDF firmado: %d bytes", len(signedPDF))

	// 7. Postear resultado al stservlet.
	if err := storage.PostResult(params.StServlet, params.SessionID, token.CertificateDER(), signedPDF); err != nil {
		return fmt.Errorf("PostResult: %w", err)
	}
	log.Println("Firma enviada al backend. Cerrando.")
	return nil
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
