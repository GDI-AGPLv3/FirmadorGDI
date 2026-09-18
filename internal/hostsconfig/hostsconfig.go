// Package hostsconfig lee los servidores que el administrador autorizó al
// instalar, además de los que vienen compilados en internal/uri.
//
// ── Para qué existe ─────────────────────────────────────────────────────────
//
// El binario trae compilados los hosts de GDI (los cuatro `enlace-*`). Una
// instalación on-premise firma contra el servidor del municipio
// (`api.su-municipio.gob.ar`), que no puede estar en esa lista: no lo conocemos
// al compilar, y hacer una release por cliente no escala.
//
// Entonces el MSI lo pregunta en la instalación y lo guarda acá. Un solo
// instalador sirve para el SaaS y para todos los on-premise.
//
// ── Por qué el registro y no un archivo ─────────────────────────────────────
//
// Porque lo que decide si esto es seguro o es un agujero es QUIÉN puede
// escribirlo.
//
//   - `HKEY_LOCAL_MACHINE` necesita permisos de administrador. El MSI corre
//     elevado, así que puede escribirlo al instalar; después, un usuario común
//     —el funcionario— no puede tocarlo.
//   - Un archivo junto al .exe, una variable de entorno o `HKCU` los escribe el
//     propio usuario. Con cualquiera de esos, una página maliciosa que logre
//     ejecutar algo como el usuario se autoriza sola, y volvemos a FG-001.
//
// El ataque que cerró FG-001 es REMOTO: un link `gdifirma://` con el servidor
// del atacante adentro. Ese atacante no escribe en HKLM. Lo que queda posible es
// la ingeniería social —convencer al área de sistemas de agregar un host—, y
// contra eso la defensa es que el diálogo del PIN muestre SIEMPRE el servidor
// (1.5.0): el funcionario ve el nombre antes de poner el PIN.
package hostsconfig

// RutaRegistro es dónde vive la lista, documentado acá para que el instalador y
// el soporte miren el mismo lugar.
const RutaRegistro = `HKLM\SOFTWARE\GDILatam\FirmadorGDI`

// NombreValor es el valor del registro que guarda los hosts.
const NombreValor = "HostsAutorizados"
