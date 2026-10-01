# FirmadorGDI — contexto del repo

Cliente de escritorio (Go; Windows y, desde la 1.8.0, macOS) que firma PDFs con
el token físico del funcionario. Lo lanza el navegador vía el scheme
`gdifirma://`. Repo **público**, AGPL-3.0.

## Lo primero que hay que saber: el binario es agnóstico del ambiente

No hay una compilación "de DEV" y otra "de PRD". Las URLs del servidor
—`rtservlet` y `stservlet`— **llegan en la URI** que arma el backend
(`internal/uri/parse.go`), no están hardcodeadas en ningún lado:

```
gdifirma://sign?ver=1_0&fileid=X&rtservlet=https://…&stservlet=https://…&id=W&keystore=PKCS11
```

Consecuencia práctica: **el mismo MSI sirve para los tres ambientes**. Un
funcionario instala una vez y firma contra DEV, HML o PRD según desde dónde
haya entrado. Por eso se publica **un solo instalador**, el de PRD.

> ⚠️ Agnóstico del ambiente **no** quiere decir que acepte cualquier servidor.
> `HostsPermitidos` (en `internal/uri/parse.go`) es la lista de hosts a los
> que el programa le obedece, **escritos completos y comparados exactos**: los
> cuatro backends (`gdi-backend-dev`, `demo-backend-prd`, `aries-backend-prd`,
> `arg-backend-prd`, todos `.fly.dev`), `enlace.gdilatam.com` y local. Existe
> porque, una vez instalado, **cualquier página que el funcionario abra puede
> lanzar un `gdifirma://`** — y las URLs del servidor viajan dentro del link.
> Sin la lista, un link ajeno lograba que el token firmara documentos que el
> funcionario nunca vio, y con el modo lote son cinco por un solo PIN.
>
> **El dialogo del PIN dice a que servidor van las firmas** (1.5.0). Es la
> defensa que no depende de la lista: si alguien logra que se autorice un host
> —convenciendo al area de sistemas, por ejemplo—, el funcionario ve el nombre
> raro antes de poner el PIN. El host se setea con `.Text` DESPUES del
> `XamlReader::Load`, nunca interpolado en el XAML (ver FG-009), y hay tests en
> `internal/ui/dialog_windows_test.go` que lo exigen y que validan que el XAML
> sea XML valido.
>
> **Nada de sufijos en esa lista** (FG-001, 04/09/2026): hasta la versión 1.4.2
> decía `.fly.dev`, y fly.dev es hosting compartido — cualquiera publicaba
> `lo-que-sea.fly.dev` con TLS válido y quedaba autorizado. Un test
> (`TestLaListaNoTieneSufijos`) falla si alguien vuelve a poner uno.
>
> **Una instalación on-premise autoriza su propio servidor EN LA INSTALACIÓN**
> (GDI-532), sin compilar nada. Desde la 1.7.0 el asistente lo **pregunta**: dos
> opciones —«Uso GDI Latam en la nube» (marcada por defecto) y «Mi organismo
> tiene GDI en su propio servidor», que habilita el campo de la dirección—. Sigue
> andando el parámetro, para instalaciones desatendidas:
> `msiexec /i FirmadorGDI.msi SERVIDORGDI="api.su-municipio.gob.ar"`.
> El host queda en `HKLM\SOFTWARE\GDILatam\FirmadorGDI`, valor `HostsAutorizados`, que
> **pide permisos de administrador**: el MSI corre elevado y puede escribirlo; el
> funcionario después no. Para cambiarlo, se reinstala.
>
> Por eso HKLM y no un archivo junto al .exe, ni una variable de entorno, ni HKCU:
> esos tres los escribe el propio usuario, y con cualquiera de ellos algo que corra
> como el usuario se autoriza solo — FG-001 con pasos extra. El ataque de FG-001 es
> REMOTO (un link con el servidor del atacante adentro) y ese atacante no escribe en
> HKLM. Lo que queda posible es la ingeniería social —convencer al área de sistemas—,
> y contra eso está el cartel del servidor en el diálogo del PIN (1.5.0).
>
> Lo que entra por esa puerta se valida: hosts pelados, sin sufijos, comodines,
> esquemas, puertos ni barras. Un solo sufijo ahí reabriría FG-001 entero.

> ⚠️ El parámetro `ver` se parsea pero **nunca se valida** (`validate()` no lo
> mira). Subirlo a `1_1` no rompe nada por sí solo — hay que tenerlo presente
> antes de asumir que un cliente viejo va a rechazar una URI nueva: no lo hace.

## Ramas y ambientes (GDI-341)

Mismo flujo escalonado que el resto del ecosistema, con una diferencia: acá la
rama de producción es **`main`**, no `prd`.

| Rama | Para qué |
|------|----------|
| `dev` | integración; se prueba con build local (`go build ./cmd/firmadorgdi`) |
| `hml` | homologación contra ARIES |
| `main` | **producción** — es la rama que ve el mundo y de la que sale el MSI publicado |

Flujo: `dev` → `hml` → `main`.

**Por qué `main` se queda como producción** (decisión de Santiago, 20/08/2026):
es un repo público. Renombrarla rompería los links `/blob/main/…` que ya están
publicados, los forks y cualquier clon que alguien tenga. El costo de la
consistencia nominal con los otros repos es mayor que el beneficio.

## Versionado

`internal/version/version.go` es la **única fuente de verdad**. La constante
`Version` de ahí y el atributo `Version` de `installer/firmadorgdi.wxs` se
actualizan **juntos**: `internal/version/version_test.go` falla si difieren.

La versión se ve en tres lugares, y eso es el punto de GDI-341 —antes no se veía
en ninguno—:

```
firmadorgdi.exe --version     # FirmadorGDI 1.2.0
```

> ⚠️ Eso funciona **solo porque `main()` llama a `engancharConsola()` antes de
> imprimir**. Con `-H windowsgui` Windows no le da consola al proceso y el
> `Printf` escribe en un handle vacío. La función estuvo escrita —y dada por
> funcionando en dos commits— sin que nadie la invocara: `--version` no imprimía
> una sola línea. Hay un test que ahora exige la llamada
> (`cmd/firmadorgdi/main_test.go`); si alguien la saca, el test avisa.

- el diálogo que aparece al abrirlo sin argumentos,
- la primera línea de `%TEMP%\firmadorgdi.log`, en cada corrida.

Sin esto, un municipio reportando un problema era una adivinanza: no hay
auto-update ni telemetría, así que la única forma de saber qué versión corre es
que el binario lo diga.

### Publicar una versión

1. Subir `Version` en `internal/version/version.go` **y** en `firmadorgdi.wxs`.
2. `go test ./...` — el test de coherencia es la red.
3. Merge a `main`.
4. Tag: `git tag -a v1.1.0 -m "…"` y push del tag. El tag es lo que ata el MSI
   publicado a un commit exacto; sin él, "la versión que está en producción" no
   es una pregunta con respuesta.
5. Compilar el MSI:

   ```
   go build -ldflags="-H windowsgui -s -w" -o firmadorgdi.exe ./cmd/firmadorgdi
   cd installer
   wix build firmadorgdi.wxs -ext WixToolset.UI.wixext -o FirmadorGDI-<version>.msi
   ```

   ⚠️ **Verificar que NO quede un `cab1.cab` al lado del `.msi`.** Si queda, el
   instalador publicado no sirve: al ejecutarlo pide *"Source file not found:
   cab1.cab"*. Lo garantiza `<MediaTemplate EmbedCab="yes" />` en el `.wxs`, y
   hay un test que lo exige (`internal/version/version_test.go`). Pasó de verdad
   al compilar la 1.2.0: el `.wxs` nunca lo había declarado.

6. Publicarlo como `FirmadorGDI-latest.msi`
   (`https://firmadorgdi.gdilatam.com/FirmadorGDI-latest.msi`, que es el link que
   muestra el frontend al firmar).
7. El `.pkg` de macOS sale del workflow `macOS` (artefacto `FirmadorGDI-macos`
   de la corrida del tag). Se publica **en el mismo bucket y dominio** que el
   MSI, como `FirmadorGDI-latest.pkg`
   (`https://firmadorgdi.gdilatam.com/FirmadorGDI-latest.pkg`): el frontend
   elige `.msi` o `.pkg` según la computadora (`useDescargaFirmador.ts` en
   `GDI-FRONTEND`). No hay un dominio aparte para Mac. Ver la sección **macOS**
   más abajo.

   ⚠️ **Orden:** el `.pkg` se publica ANTES de que el frontend con el link de
   Mac llegue a un ambiente. Al revés, una Mac recibe un link que da 404.

**No hay que desinstalar la versión anterior:** el `UpgradeCode` es fijo y el
`.wxs` declara `MajorUpgrade`, así que Windows reemplaza sola la que esté.

**Un solo MSI publicado**, sin alias `-dev` ni `-hml` (decisión de Santiago,
20/08/2026): para probar un cambio se compila local y se instala a mano. Mantener
tres instaladores publicados para un binario que no cambia entre ambientes es
trabajo sin beneficio.

## Cómo se entera un municipio de que hay versión nueva (GDI-341)

**No hay auto-update.** El programa no consulta si hay versión nueva, no la baja
y no avisa por sí mismo. Lo que hay, desde la 1.3.0, es esto:

1. El firmador manda su versión en **cada pedido** al servidor
   (`X-FirmadorGDI-Version`, en `internal/storage/client.go` — se agrega con un
   RoundTripper, así vale para todas las llamadas).
2. El backend la guarda (`digital_signature_sessions.client_version`, migración
   119) y la compara contra `FIRMADOR_VERSION_MINIMA` (`config/constants.py`).
3. La pantalla de firma le muestra el cartel con el link de descarga.

Va **solo la versión**: nada del equipo, del usuario ni del token.

**Cuándo subir `FIRMADOR_VERSION_MINIMA`**: cuando la versión nueva trae algo que
de verdad importa —un arreglo de seguridad, un cambio de protocolo que rompe— y
**no en cada release**. Es una variable de entorno, se mueve sin deploy. Un aviso
permanente que el funcionario no puede sacarse de encima se vuelve parte del
paisaje y deja de leerse.

> ⚠️ Nunca la pongas por encima de la versión que está publicada: todos verían un
> cartel pidiendo algo que no se puede descargar. Hay un test que lo impide
> (`GDI-Backend/tests/test_gdi341_version_del_firmador.py`), pero solo corre si
> los dos repos están uno al lado del otro.

## Qué driver se usa cuando hay varios instalados (1.8.0)

`pkcs11.Open` recorre `KnownDrivers` y usa **el primero que ve un token
conectado y lo puede abrir** (`internal/pkcs11/seleccion.go`). Hasta la 1.7.0
usaba el primero que *cargaba*: en una máquina con los middlewares de Feitian y
de SafeNet y un token SafeNet enchufado, el de Feitian cargaba, decía "cero
tokens" y el programa cortaba con "no hay tokens conectados" sin preguntarle
nunca al de SafeNet.

- El orden de `KnownDrivers` es solo el desempate: los del fabricante antes que
  OpenSC, que es genérico y a veces "ve" tokens de otra marca sin poder usarlos.
- Los drivers descartados se cierran (`Finalize` + `Destroy`) antes de probar el
  siguiente: dos middlewares inicializados sobre el mismo lector se pisan.
- Los errores ya no se confunden: sin ningún driver, *"no se encontró driver
  PKCS#11 compatible"* (la documentación de usuario cita ese texto tal cual);
  con drivers pero sin token, *"no hay tokens conectados"* y la lista de los
  que se probaron.
- El log dice qué driver se eligió y por qué se descartó cada uno de los otros.
- Con **dos tokens enchufados a la vez** toma el primero que encuentra. No hay
  selector; es una card aparte si aparece el caso.

La decisión está cubierta por tests con drivers de mentira
(`seleccion_test.go`). **No está probada con dos middlewares reales**: hace
falta una PC con los dos instalados y el token del segundo enchufado.

## macOS (1.8.0)

El mismo programa, con tres diferencias que no son de forma:

- **El link no llega por argv.** Windows lanza `firmadorgdi.exe "gdifirma://…"`.
  macOS abre `FirmadorGDI.app` **sin argumentos** y le manda el link como un
  Apple Event. `main()` lo espera con `ui.URIDeArranque()`; sin eso el programa
  arranca, no ve nada y dice "está instalado y listo" en vez de firmar. Quién
  atiende `gdifirma://` lo declara `installer/macos/Info.plist`
  (`CFBundleURLTypes`): no hay nada que escribir al instalar, y `--register`
  solo fuerza la relectura (`lsregister`).
- **Los diálogos son AppKit vía cgo** (`internal/ui/dialog_darwin.go`), no un
  script. El borrador anterior usaba `osascript` con el label del token
  interpolado en el AppleScript: una comilla ahí se ejecutaba como código. El
  texto del diálogo lo arma `textoDelPIN` (`internal/ui/texto_pin.go`, sin build
  tag para poder probarlo en Windows) y dice lo mismo que el de Windows: token,
  cuántos documentos y **a qué servidor van las firmas**.
- **La lista de hosts on-premise vive en un archivo de root**, no en el registro:
  `/Library/Application Support/GDILatam/FirmadorGDI/HostsAutorizados`, un host
  por línea. Es el equivalente de HKLM — hace falta `sudo` para escribirlo — y
  `hostsconfig.Leer()` lo **ignora** si el archivo o su carpeta no son de root o
  los puede escribir otro. El instalador **no lo pregunta** (el de Windows sí):
  la última pantalla le deja al administrador los dos comandos. Sobrevive a las
  actualizaciones: el `.pkg` solo toca `/Applications`.

El log está en `~/Library/Logs/FirmadorGDI/firmadorgdi.log` (el `%TEMP%` de una
Mac es una ruta por usuario que nadie encuentra por teléfono).

### Cómo se arma el `.pkg`

**Desde Windows no se puede**: el binario usa cgo dos veces (el driver PKCS#11 y
AppKit) y eso pide el compilador y los frameworks de Apple. Hay dos caminos y
hacen lo mismo:

- en una Mac: `installer/macos/build.sh` → `dist/macos/FirmadorGDI-<version>.pkg`;
- sin Mac: el workflow `.github/workflows/macos.yml`, que corre el mismo script
  en un runner macOS y deja el `.pkg` como artefacto. El repo es público: no
  consume minutos.

El workflow además **instala el `.pkg` y abre un link `gdifirma://`** en el
runner, y mira el log: es la única prueba de que el instalador instala donde
tiene que instalar y de que el Apple Event llega al programa. Ningún test de Go
puede ver eso.

El binario es **universal** (arm64 + x86_64). No es por las Macs con Intel
solamente: el driver del token tiene que ser de la misma arquitectura que el
proceso, y con un middleware viejo —solo Intel— la salida es abrir FirmadorGDI
con Rosetta, que necesita la mitad x86_64.

La versión **no se escribe** en ningún archivo de macOS: `Info.plist` y
`distribution.xml` llevan `__VERSION__` y `build.sh` lo reemplaza leyendo
`version.go`. Hay un test que falla si alguien pone un número a mano.

### Lo que NO está validado

- **Ningún token se probó en una Mac.** Las rutas de `drivers_darwin.go` salen
  de la documentación de cada middleware (Feitian, SafeNet, OpenSC). El
  ePass2003 está validado en Windows, no acá.
- **El diálogo del PIN no lo vio nadie.** El runner prueba que el link llega y
  que el programa corta en "token no encontrado"; para llegar al PIN hace falta
  un token conectado.
- **Sin firma de Apple** (Developer ID + notarización), al abrir el `.pkg`
  descargado macOS dice que no puede verificar al desarrollador y hay que
  habilitarlo en Ajustes → Privacidad y seguridad → "Abrir igualmente". Es el
  equivalente de SmartScreen, más hostil. `build.sh` ya firma y notariza si se
  le pasan `FIRMA_APP`, `FIRMA_INSTALADOR` y `NOTARIA_PERFIL`; lo que falta es
  la cuenta de Apple Developer. Con firma, `entitlements.plist` es obligatorio:
  sin `disable-library-validation` el programa notarizado no puede cargar el
  driver del token.

## Fuera de alcance (a propósito)

- **Auto-update de verdad**: instalar software en una máquina municipal suele
  pedir permisos de administrador, y sin firma Authenticode Windows muestra su
  advertencia en cada actualización. Con el aviso de arriba se cubre el 90% del
  problema a una fracción del costo.
- **CI en GitHub Actions para el MSI**: el MSI se sigue compilando a mano. Vale
  la pena cuando haya releases seguidas, no antes. (El `.pkg` de macOS sí sale
  de Actions, porque no hay otra forma de compilarlo sin una Mac.)
- **Firma Authenticode del ejecutable**: hace falta un certificado de firma de
  código. Sin él, Windows SmartScreen sigue mostrando la advertencia al
  instalar. Es una card aparte.
- **Firma de Apple (Developer ID)**: lo mismo del lado de macOS. Ver arriba.

## El protocolo cambió en 1.4.0: el PDF ya no viaja (GDI-405)

Hasta 1.3.1 el servidor mandaba el PDF entero dentro del envelope, el firmador
lo firmaba en la máquina del funcionario y devolvía el PDF firmado. Un
expediente de 19 MB cruzaba dos veces una conexión municipal para que al token
le llegaran, al final, 32 bytes.

Ahora el PDF se queda en el servidor. El firmador pide el PIN **primero** —sin
token abierto no hay certificado, y sin certificado el servidor no puede
preparar nada— y después intercambia cuatro mensajes por el mismo transporte de
siempre (`op=get` / `op=put`, form-urlencoded):

1. `op=get` → envelope `v="2"` con `mode=digest`, **sin** `dat`.
2. `op=put` → `CERT:` + certificado DER del token en base64url.
3. `op=get` en bucle → `PENDING` mientras el servidor estampa el sello y arma
   el CMS contra Notary; después `DIGESTS:` + JSON base64url
   `[{"id", "digest_b64"}]`. El presupuesto es de **120 s en total** (no de N
   intentos), con la espera creciendo de 500 ms a 2 s. Notary corre con
   `min_machines_running=0`: el primer pedido paga el arranque en frío, y en
   una tanda las N preparaciones esperan atrás. El techo lo pone
   `DIGITAL_SIGNATURE_SESSION_TTL` (240 s del lado del servidor): rendirse
   antes deja al funcionario con un timeout DESPUÉS del PIN y los números
   reservados hasta que la sesión venza.
4. `op=put` → `SIGS:` + JSON base64url `[{"id", "sig_b64"}]`.

La tanda hace los mismos cuatro pasos con N ids: **un** CERT, **un** poll y
**un** SIGS para todos los documentos. El manifiesto pasó a `v="1_2"`.

Dos cosas que no son evidentes:

- **El largo del digest se valida acá** (`storage.DigestItem.Digest`, 32 bytes).
  El token firma a ciegas: `tokenSigner.Sign` le antepone el DigestInfo de
  SHA-256 sin mirar qué recibe, así que un digest de otro tamaño produciría una
  firma válida sobre algo que no es un SHA-256.
- **No hay fallback al protocolo viejo.** `internal/signing` se borró junto con
  sus dependencias (digitorus/pdfsign, fogleman/gg): el binario ya no sabe
  firmar un PDF. Un envelope con `dat` corta con un error que le dice al
  funcionario que actualicen el servidor. El cruce no ocurre en la práctica
  porque el servidor se deploya antes que el MSI.

## Estructura

```
cmd/firmadorgdi/    main: URI handler, --register, --version
internal/uri/       parseo de gdifirma:// (parse.go — acá viven rtservlet/stservlet)
internal/pkcs11/    acceso al token físico
internal/storage/   subida/bajada contra los servlets del backend
internal/ui/        diálogos nativos: WPF en Windows, AppKit en macOS
internal/version/   la versión, y los tests que la atan al MSI y al .pkg
installer/          WiX v4 (firmadorgdi.wxs)
installer/macos/    .app + .pkg de macOS (build.sh)
```

## Del lado del servidor

El backend arma la URI en `services/documents/signing/providers/firmador_gdi.py`
(repo `GDI-Backend`) y atiende los dos servlets en
`endpoints/digital_signature/storage.py`. Dos cosas que conviene tener a mano:

- el identificador de sesión **ES la credencial** de ese endpoint (no hay JWT),
  por eso tiene 128 bits de entropía y rate-limit por IP (GDI-242, GDI-272);
- desde 1.4.0 **no vuelve ningún PDF**, así que la comparación de GDI-273 ya no
  aplica. La reemplaza un binding más fuerte: el backend verifica que la firma
  que devolvió el token sea una RSA PKCS#1 v1.5 válida del digest que él mismo
  mandó, con la clave pública del certificado que el token declaró (GDI-405).
