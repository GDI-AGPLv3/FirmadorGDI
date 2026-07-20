> 🇬🇧 **English summary** — FirmadorGDI is the digital-signature service of **GDI (Gestión Documental Inteligente)**, written in **Go**: PDF signing workflows compliant with Argentina's Digital Signature Law 25.506. Part of GDI, an open-source (AGPL-3.0) document-management platform for local governments in Latin America. Live product: [gdilatam.com](https://www.gdilatam.com).

# FirmadorGDI

> Firma PDFs con tu token físico (eToken, ePass2003, YubiKey) desde el navegador.  
> Drop-in replacement de AutoFirma España para municipios de América Latina.

## El problema

AutoFirma España pesa ~80 MB, requiere Java 21 y se rompe constantemente con cada actualización del navegador. Los SaaS internacionales (DocuSign, etc.) no soportan tokens hardware locales como el eToken de la AC ONTI Argentina.

## La solución

Un binario Go de ~10 MB, sin runtime externo, que:

1. Chrome lanza automáticamente cuando el sistema de gestión documental dice "firmar"
2. Muestra un diálogo moderno con el token detectado y un campo PIN
3. Firma el PDF con tu clave privada — la clave **nunca sale del token**
4. Devuelve el PDF firmado al sistema

```
Chrome  →  gdifirma://sign?...  →  FirmadorGDI.exe
                                        ↓ PKCS#11
                                  Token físico (ePass2003)
                                        ↓
                                  PDF firmado (PAdES)
                                        ↓
                                  Backend GDI
```

## Estado

🟢 **Sprint 2 completo — MSI distribuido, E2E validado**

| Componente | Estado |
|------------|--------|
| Stack Go + PAdES + sello visible | ✅ Validado |
| Token ePass2003 Feitian (AC ONTI AR) | ✅ Validado |
| URI handler `gdifirma://` en Chrome / Windows | ✅ Validado |
| HTTP storage/retriever (protocolo @firma 1.9) | ✅ Validado |
| Diálogo PIN moderno — tema oscuro WPF | ✅ Validado |
| Retry PIN con feedback visual (máx. 3 intentos) | ✅ Validado |
| Detección de token bloqueado (`CKR_PIN_LOCKED`) | ✅ Validado |
| CUIL + vencimiento del cert en diálogo (sin login) | ✅ Validado |
| E2E completo (Chrome → token físico → PDF firmado) | ✅ Validado |
| Sin flash de consola — `HideWindow` a nivel SO | ✅ Validado |
| Instalador MSI (WiX v7, sin admin) | ✅ Validado |
| Sello visual idéntico a la firma electrónica (Courier, 4 líneas) | ✅ Validado |
| Code signing (Azure Trusted Signing) | ❌ Descartado por ahora |
| macOS | 🔧 Sprint 3 |

## Compatibilidad

| Token | SO | Estado |
|-------|----|--------|
| Feitian ePass2003 (AC ONTI Argentina) | Windows 11 | ✅ Validado |
| SafeNet eToken | Windows | ⏳ Sin probar |
| YubiKey (PKCS#11) | Windows | ⏳ Sin probar |
| Cualquier token PKCS#11 estándar | Windows | Debería funcionar |

## Diferencias vs AutoFirma España

| | AutoFirma España 1.9 | FirmadorGDI v1 |
|---|---|---|
| Tamaño | ~80 MB | ~10 MB |
| Runtime | Java 21 requerido | Sin runtime externo |
| URI scheme | `afirma://` | `gdifirma://` (coexiste) |
| Formatos | PAdES + CAdES + XAdES | PAdES |
| Plataformas | Win / Mac / Linux | Windows V1, macOS Sprint 3 |
| UI | Java Swing | WPF nativo (tema oscuro) |
| Visor PDF | Sí | No (está en el sistema de gestión) |
| Licencia | EUPL 1.1 | AGPL v3 |

## Instalación

### Opción 1 — MSI (recomendado)

Descargar `FirmadorGDI-x.x.x.msi` de [Releases](https://github.com/GDI-AGPLv3/FirmadorGDI/releases) y ejecutar. No requiere permisos de administrador.

### Opción 2 — Compilar desde fuente

Requiere Go 1.22+ y GCC (CGO).

```bash
# Windows con scoop
scoop install go gcc

git clone https://github.com/GDI-AGPLv3/FirmadorGDI
cd FirmadorGDI

CGO_ENABLED=1 go build -ldflags "-s -w -H windowsgui" -o firmadorgdi.exe ./cmd/firmadorgdi

# Registrar URI scheme (una vez por instalación, sin admin)
.\firmadorgdi.exe --register
```

## Protocolo

Compatible con @firma 1.9 — el mismo protocolo que usa AutoFirma España. El backend genera una URI `gdifirma://sign?...` que Chrome entrega al binario.

Referencia técnica: `docs/protocolo-afirma.md` *(próximamente)*.

## Arquitectura interna

```
cmd/firmadorgdi/main.go         entrypoint — orquesta el flujo completo
internal/uri/parse.go           parseo y validación de gdifirma://
internal/storage/client.go      cliente HTTP storage/retriever (@firma)
internal/pkcs11/token.go        PKCS#11: detectar token, login, signer
internal/signing/pdf.go         firmar PDF con PAdES + sello visible 4 líneas
internal/ui/dialog.go           tipos compartidos (TokenInfo, PINResult)
internal/ui/dialog_windows.go   diálogo WPF — tema oscuro (build tag windows)
internal/ui/dialog_darwin.go    diálogo osascript / Cocoa (build tag darwin)
installer/                      WiX v7 — MSI sin admin, URI scheme HKCU
```

## Log de depuración

El binario escribe en `%TEMP%\firmadorgdi.log`. Útil para soporte.

## Licencia

AGPL v3 — ver [LICENSE](LICENSE).

Copyright (C) 2026 [Tecnología Acuario](https://gdilatam.com).  
Desarrollado por el equipo de [GDI Latam](https://gdilatam.com).  
Dual licensing comercial disponible — contacto: santiago@gdilatam.com
