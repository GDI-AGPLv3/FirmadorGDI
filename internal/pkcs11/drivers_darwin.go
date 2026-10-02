//go:build darwin

package pkcs11

// Drivers conocidos en macOS. Se prueban en orden hasta encontrar uno que cargue.
//
// Son las rutas donde el instalador de cada fabricante deja su librería
// PKCS#11. Mismo orden que en Windows: Feitian, SafeNet, OpenSC.
//
// ⚠️ NINGUNA está validada con un token real en una Mac (el ePass2003 se
// validó en Windows). Salen de la documentación de cada middleware. Cuando un
// municipio pruebe, la primera línea de `~/Library/Logs/FirmadorGDI/firmadorgdi.log`
// después del arranque dice qué token se detectó; si dice "no se encontró
// driver", falta acá la ruta de su middleware.
//
// ⚠️ La librería tiene que ser de la misma arquitectura que el proceso. El
// binario es universal (arm64 + x86_64); un middleware viejo, solo Intel, no
// carga en una Mac con Apple Silicon salvo que se abra FirmadorGDI con Rosetta
// (Finder → Obtener información → "Abrir con Rosetta").
var KnownDrivers = []string{
	"/usr/local/lib/libcastle_v2.1.0.0.dylib",                               // Feitian ePass2003 (middleware actual)
	"/usr/local/lib/libcastle.1.0.0.dylib",                                  // Feitian ePass2003 (middleware anterior)
	"/usr/local/lib/libeTPkcs11.dylib",                                      // SafeNet eToken (SafeNet Authentication Client)
	"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib", // SafeNet, sin el enlace de /usr/local/lib
	"/Library/OpenSC/lib/opensc-pkcs11.so",                                  // OpenSC (instalador oficial)
	"/opt/homebrew/lib/opensc-pkcs11.so",                                    // OpenSC (Homebrew, Apple Silicon)
	"/usr/local/lib/opensc-pkcs11.so",                                       // OpenSC (Homebrew, Intel)
}
