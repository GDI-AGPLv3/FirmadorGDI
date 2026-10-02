//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/" +
	"LaunchServices.framework/Support/lsregister"

// registerURIScheme le pide a macOS que vuelva a leer el .app.
//
// En macOS no hay nada que escribir: quién atiende gdifirma:// lo declara el
// Info.plist del .app (CFBundleURLTypes) y el sistema lo registra solo al
// instalarlo. Esto queda para soporte, cuando una Mac no asocia el link: fuerza
// la relectura. Suelto, fuera de un .app, el binario no tiene Info.plist y no
// hay nada que registrar.
func registerURIScheme() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}

	// …/FirmadorGDI.app/Contents/MacOS/firmadorgdi
	bundle := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if !strings.HasSuffix(bundle, ".app") {
		return fmt.Errorf(
			"en macOS el link gdifirma:// lo registra el sistema al instalar FirmadorGDI.app; "+
				"este binario está suelto (%s)", exe)
	}
	if out, err := exec.Command(lsregister, "-f", bundle).CombinedOutput(); err != nil {
		return fmt.Errorf("lsregister %s: %v (%s)", bundle, err, strings.TrimSpace(string(out)))
	}
	return nil
}
