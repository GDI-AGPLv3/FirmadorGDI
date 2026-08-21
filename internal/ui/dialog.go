// Package ui muestra diálogos nativos del SO para interacción con el usuario.
// Cada plataforma tiene su implementación en un archivo separado:
//   dialog_windows.go  →  Win32 (CreateWindowEx + ES_PASSWORD)
//   dialog_darwin.go   →  Cocoa via CGO (NSAlert + NSSecureTextField)
//
// El contrato es único: PINDialog recibe info del token, devuelve PIN o error.
package ui

import "errors"

// ErrCancelled se devuelve cuando el usuario cancela el diálogo.
var ErrCancelled = errors.New("el usuario canceló la firma")

// TokenInfo es lo que se muestra en el diálogo al usuario.
type TokenInfo struct {
	Label        string // "PEREZ, Juan"
	Manufacturer string // "EnterSafe by Feitian"
	Subject      string // "PEREZ Juan"
	SerialNumber string // "CUIL 20123456789"
	ValidUntil   string // "31/12/2030"
	WrongPIN     bool   // true si el intento anterior falló
	// GDI-167: cuántos documentos se van a firmar con este PIN. 0 o 1 = firma
	// de a una y el diálogo no cambia. Con más, el cartel lo dice de frente:
	// autorizar una tanda sin saber cuántos documentos incluye no es autorizar
	// nada (condición D1-bis de la decisión que habilitó la feature).
	BatchCount   int
}

// PINResult es lo que devuelve el diálogo.
type PINResult struct {
	PIN       string
	Cancelled bool
}

func (info TokenInfo) WithWrongPIN() TokenInfo {
	info.WrongPIN = true
	return info
}

// ShowPINDialog muestra un diálogo nativo pidiendo el PIN del token.
// Bloquea hasta que el usuario acepta o cancela.
// Implementado por plataforma en dialog_windows.go / dialog_darwin.go.

// ShowInfoDialog muestra un diálogo informativo con estilo GDI.
// Bloquea hasta que el usuario hace clic en Aceptar.

// ShowErrorDialog muestra un diálogo de error con estilo GDI.
// Bloquea hasta que el usuario hace clic en Aceptar.
