//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

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
