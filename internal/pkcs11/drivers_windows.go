//go:build windows

package pkcs11

// Drivers conocidos. Se prueban en orden hasta encontrar uno que cargue.
var KnownDrivers = []string{
	`C:\Windows\System32\eps2003csp11.dll`,  // Feitian ePass2003
	`C:\Windows\System32\eTPKCS11.dll`,      // SafeNet eToken
	`C:\Windows\System32\opensc-pkcs11.dll`, // OpenSC (genérico)
}
