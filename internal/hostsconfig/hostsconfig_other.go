//go:build !windows && !darwin

package hostsconfig

const origen = "sin soporte en esta plataforma"

// Leer no hace nada fuera de Windows y macOS, que son las plataformas con
// instalador. Existe para que el paquete compile en las máquinas de desarrollo.
func Leer() []string { return nil }
