//go:build !darwin

package ui

// URIDeArranque solo hace algo en macOS, donde el link gdifirma:// llega como
// un Apple Event y no por argv (ver dialog_darwin.go). En el resto el link ya
// vino en os.Args y no hay nada que esperar.
func URIDeArranque() string { return "" }
