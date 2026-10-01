//go:build !windows && !darwin

package main

import "errors"

func registerURIScheme() error {
	return errors.New("registrar gdifirma:// solo está soportado en Windows y macOS")
}
