//go:build !windows && !darwin

package pkcs11

// Solo para compilar y probar en una máquina de desarrollo: no hay instalador
// para Linux.
var KnownDrivers = []string{
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/lib64/opensc-pkcs11.so",
	"/usr/lib/opensc-pkcs11.so",
}
