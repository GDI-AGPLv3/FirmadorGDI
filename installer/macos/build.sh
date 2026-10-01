#!/bin/bash
# Arma el instalador de macOS: dist/macos/FirmadorGDI-<version>.pkg
#
# Corre en una Mac (o en el runner macOS de GitHub Actions: .github/workflows/macos.yml).
# Desde Windows no se puede: el binario usa cgo —el driver PKCS#11 del token y
# AppKit para los diálogos— y eso necesita el compilador y los frameworks de Apple.
#
#   installer/macos/build.sh
#
# Sin variables, firma "ad-hoc": instala y funciona, pero al abrir el .pkg
# descargado macOS avisa que no conoce al desarrollador (es el equivalente del
# aviso de SmartScreen del MSI). Para que no avise hace falta una cuenta de
# Apple Developer; con ella:
#
#   FIRMA_APP="Developer ID Application: … (TEAMID)" \
#   FIRMA_INSTALADOR="Developer ID Installer: … (TEAMID)" \
#   NOTARIA_PERFIL="perfil-de-notarytool" \
#   installer/macos/build.sh
#
# NOTARIA_PERFIL es un perfil guardado con `xcrun notarytool store-credentials`.

set -euo pipefail

cd "$(dirname "$0")/../.."
RAIZ="$(pwd)"
MAC="$RAIZ/installer/macos"
SALIDA="$RAIZ/dist/macos"
ID="com.gdilatam.firmadorgdi"

# La versión sale de version.go, que es la única fuente de verdad: ni el
# Info.plist ni el guion del instalador llevan un número escrito a mano.
VERSION="$(sed -n 's/^const Version = "\([0-9.]*\)".*$/\1/p' internal/version/version.go)"
if [ -z "$VERSION" ]; then
	echo "ERROR: no se pudo leer la versión de internal/version/version.go" >&2
	exit 1
fi
echo "== FirmadorGDI $VERSION para macOS"

rm -rf "$SALIDA"
mkdir -p "$SALIDA"

# ── 1. Binario universal (Apple Silicon + Intel) ─────────────────────────────
#
# Universal y no solo arm64, por dos razones: todavía hay Macs con Intel, y el
# driver del token tiene que ser de la misma arquitectura que el proceso — con
# un middleware viejo, solo Intel, la salida es abrir FirmadorGDI con Rosetta, y
# para eso tiene que traer la mitad x86_64.
export MACOSX_DEPLOYMENT_TARGET=12.0
for arch in arm64 amd64; do
	echo "== compilando $arch"
	CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" \
		go build -trimpath -ldflags="-s -w" -o "$SALIDA/firmadorgdi-$arch" ./cmd/firmadorgdi
done
lipo -create -output "$SALIDA/firmadorgdi" "$SALIDA/firmadorgdi-arm64" "$SALIDA/firmadorgdi-amd64"
lipo -info "$SALIDA/firmadorgdi"

# ── 2. FirmadorGDI.app ───────────────────────────────────────────────────────
APP="$SALIDA/raiz/Applications/FirmadorGDI.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$SALIDA/firmadorgdi" "$APP/Contents/MacOS/firmadorgdi"
chmod 755 "$APP/Contents/MacOS/firmadorgdi"
cp "$MAC/firmadorgdi.icns" "$APP/Contents/Resources/firmadorgdi.icns"
sed "s/__VERSION__/$VERSION/g" "$MAC/Info.plist" > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist"

# El binario que se empaqueta tiene que decir la misma versión que el paquete.
DICE="$("$APP/Contents/MacOS/firmadorgdi" --version)"
if [ "$DICE" != "FirmadorGDI $VERSION" ]; then
	echo "ERROR: el binario dice '$DICE' y el paquete es $VERSION" >&2
	exit 1
fi

# ── 3. Firma del .app ────────────────────────────────────────────────────────
if [ -n "${FIRMA_APP:-}" ]; then
	echo "== firmando con Developer ID"
	codesign --force --options runtime --timestamp \
		--entitlements "$MAC/entitlements.plist" --sign "$FIRMA_APP" "$APP"
else
	echo "== firma ad-hoc (sin Developer ID: macOS va a avisar al abrir el .pkg descargado)"
	codesign --force --sign - "$APP"
fi
codesign --verify --strict --verbose=2 "$APP"

# ── 4. Paquete ───────────────────────────────────────────────────────────────
#
# BundleIsRelocatable=false. Por defecto pkgbuild marca el .app como
# "reubicable": si en esa Mac ya hay OTRA copia de FirmadorGDI.app en cualquier
# carpeta —la que quedó en Descargas, por ejemplo—, el instalador actualiza ESA
# y no pone nada en /Applications. Queda "instalado" y sin instalar.
pkgbuild --analyze --root "$SALIDA/raiz" "$SALIDA/componentes.plist"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$SALIDA/componentes.plist"

chmod 755 "$MAC/scripts/postinstall"
mkdir -p "$SALIDA/paquetes"
pkgbuild \
	--root "$SALIDA/raiz" \
	--component-plist "$SALIDA/componentes.plist" \
	--identifier "$ID" \
	--version "$VERSION" \
	--install-location / \
	--scripts "$MAC/scripts" \
	"$SALIDA/paquetes/componente.pkg"

mkdir -p "$SALIDA/recursos"
cp "$MAC/recursos/"* "$SALIDA/recursos/"
cp "$RAIZ/installer/license.rtf" "$SALIDA/recursos/license.rtf"
sed "s/__VERSION__/$VERSION/g" "$MAC/distribution.xml" > "$SALIDA/distribution.xml"

PKG="$SALIDA/FirmadorGDI-$VERSION.pkg"
FIRMA=()
if [ -n "${FIRMA_INSTALADOR:-}" ]; then
	FIRMA=(--sign "$FIRMA_INSTALADOR" --timestamp)
fi
productbuild \
	--distribution "$SALIDA/distribution.xml" \
	--resources "$SALIDA/recursos" \
	--package-path "$SALIDA/paquetes" \
	${FIRMA[@]+"${FIRMA[@]}"} \
	"$PKG"

# ── 5. Notarización (solo con Developer ID) ──────────────────────────────────
if [ -n "${NOTARIA_PERFIL:-}" ]; then
	echo "== notarizando"
	xcrun notarytool submit "$PKG" --keychain-profile "$NOTARIA_PERFIL" --wait
	xcrun stapler staple "$PKG"
fi

echo "== listo: $PKG"
ls -lh "$PKG"
