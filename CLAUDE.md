# FirmadorGDI — contexto del repo

Cliente de escritorio (Go, Windows) que firma PDFs con el token físico del
funcionario. Lo lanza Chrome vía el scheme `gdifirma://`. Repo **público**,
AGPL-3.0.

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
> `DominiosPermitidos` (en `internal/uri/parse.go`) es la lista de hosts a los
> que el programa le obedece: `*.gdilatam.com`, `*.fly.dev` y local. Existe
> porque, una vez instalado, **cualquier página que el funcionario abra puede
> lanzar un `gdifirma://`** — y las URLs del servidor viajan dentro del link.
> Sin la lista, un link ajeno lograba que el token firmara documentos que el
> funcionario nunca vio, y con el modo lote son cinco por un solo PIN.
>
> Una instalación on-premise con dominio propio **necesita que se agregue el
> suyo a esa lista y se compile una versión nueva**. No se lee de configuración
> local a propósito: quien puede escribir ese archivo podría autorizarse solo.

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

## Fuera de alcance (a propósito)

- **Auto-update de verdad**: instalar software en una máquina municipal suele
  pedir permisos de administrador, y sin firma Authenticode Windows muestra su
  advertencia en cada actualización. Con el aviso de arriba se cubre el 90% del
  problema a una fracción del costo.
- **CI en GitHub Actions**: hoy el MSI se compila a mano. Vale la pena cuando
  haya releases seguidas, no antes.
- **Firma Authenticode del ejecutable**: hace falta un certificado de firma de
  código. Sin él, Windows SmartScreen sigue mostrando la advertencia al
  instalar. Es una card aparte.

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
3. `op=get` cada 500 ms, hasta 20 veces → `PENDING` mientras el servidor
   estampa el sello y arma el CMS contra Notary; después `DIGESTS:` + JSON
   base64url `[{"id", "digest_b64"}]`.
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
internal/ui/        diálogos nativos de Windows
internal/version/   la versión, y el test que la mantiene sincronizada con el MSI
installer/          WiX v4 (firmadorgdi.wxs)
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
