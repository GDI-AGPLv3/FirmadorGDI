//go:build !windows

package hostsconfig

// Leer no hace nada fuera de Windows: el binario de producción es Windows y la
// lista vive en el registro. Existe para que el paquete compile en las
// máquinas de desarrollo.
func Leer() []string { return nil }
