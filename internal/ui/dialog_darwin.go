//go:build darwin

package ui

// Diálogos nativos de macOS (AppKit vía cgo) y recepción del link gdifirma://.
//
// ── Por qué AppKit y no osascript ───────────────────────────────────────────
//
// El borrador que había acá armaba un AppleScript INTERPOLANDO el label del
// token y el CUIL dentro del texto del script. Es FG-009 otra vez, y peor: una
// comilla en el label del token no rompía un XML, cortaba el string y lo que
// seguía se ejecutaba como AppleScript. Acá los textos viajan como datos
// (NSString), nunca como código ni como formato: no hay nada que escapar.
//
// ── Por qué el link no llega por argv ───────────────────────────────────────
//
// En Windows, Chrome lanza `firmadorgdi.exe "gdifirma://…"`. macOS no: abre el
// .app SIN argumentos y le manda el link como un Apple Event (kAEGetURL). Un
// binario que solo mira os.Args arranca, no ve nada y muestra "está instalado
// y listo" en lugar de firmar. URIDeArranque es lo que escucha ese evento.
//
// ── El hilo principal ───────────────────────────────────────────────────────
//
// AppKit solo se puede usar desde el hilo principal del proceso. El init() de
// abajo ata la goroutine main a ese hilo; por eso todo lo de este archivo se
// llama DESDE main (y desde lo que main llama en línea), nunca desde otra
// goroutine. Hoy el flujo entero de firma es secuencial y lo cumple.

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>
#include <stdlib.h>
#include <string.h>

static NSString *gdiTexto(const char *s) {
	if (s == NULL) {
		return @"";
	}
	NSString *r = [NSString stringWithUTF8String:s];
	return r != nil ? r : @"";
}

// El binario no es una app con ventanas ni ícono en el Dock: es un auxiliar que
// aparece, pide el PIN y se va. Accessory es la política que permite mostrar
// diálogos sin Dock ni barra de menú (también cuando se lo corre suelto, fuera
// del .app, que arranca en Prohibited y no puede mostrar nada).
static void gdiPrepararApp(void) {
	[NSApplication sharedApplication];
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

// Sin esto el diálogo queda DETRÁS del navegador: el funcionario hace clic en
// "Firmar", no ve nada y vuelve a hacer clic.
static void gdiAlFrente(NSAlert *alerta) {
	[[alerta window] setLevel:NSFloatingWindowLevel];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	[NSApp activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
}

static void gdiAviso(const char *titulo, const char *mensaje, int esError) {
	@autoreleasepool {
		gdiPrepararApp();
		NSAlert *alerta = [[NSAlert alloc] init];
		[alerta setMessageText:gdiTexto(titulo)];
		[alerta setInformativeText:gdiTexto(mensaje)];
		[alerta setAlertStyle:(esError ? NSAlertStyleCritical : NSAlertStyleInformational)];
		[alerta addButtonWithTitle:@"Aceptar"];
		gdiAlFrente(alerta);
		[alerta runModal];
	}
}

// Devuelve el PIN (lo libera el llamador con free) o NULL si se canceló.
static char *gdiPedirPIN(const char *titulo, const char *detalle) {
	@autoreleasepool {
		gdiPrepararApp();
		NSAlert *alerta = [[NSAlert alloc] init];
		[alerta setMessageText:gdiTexto(titulo)];
		[alerta setInformativeText:gdiTexto(detalle)];
		[alerta addButtonWithTitle:@"Firmar"];
		// NSAlert solo le da el Escape a un botón que se llame "Cancel".
		NSButton *cancelar = [alerta addButtonWithTitle:@"Cancelar"];
		[cancelar setKeyEquivalent:@"\033"];

		NSSecureTextField *pin = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
		[pin setPlaceholderString:@"PIN del token"];
		[alerta setAccessoryView:pin];
		[[alerta window] setInitialFirstResponder:pin];

		gdiAlFrente(alerta);
		if ([alerta runModal] != NSAlertFirstButtonReturn) {
			return NULL;
		}
		return strdup([[pin stringValue] UTF8String]);
	}
}

// ── El link de arranque ──────────────────────────────────────────────────────

@interface GDIArranque : NSObject <NSApplicationDelegate>
@property(copy) NSString *uri;
@property(assign) double espera;
@property(assign) BOOL lanzada;
@property(assign) BOOL corriendo;
@end

@implementation GDIArranque

// El handler se registra ACÁ y no más tarde: el evento con el link llega antes
// de applicationDidFinishLaunching, y registrado después ya se perdió.
- (void)applicationWillFinishLaunching:(NSNotification *)aviso {
	[[NSAppleEventManager sharedAppleEventManager]
	    setEventHandler:self
	        andSelector:@selector(alAbrirURL:respuesta:)
	      forEventClass:kInternetEventClass
	         andEventID:kAEGetURL];
}

- (void)alAbrirURL:(NSAppleEventDescriptor *)evento respuesta:(NSAppleEventDescriptor *)respuesta {
	[self recibir:[[evento paramDescriptorForKeyword:keyDirectObject] stringValue]];
}

// La misma entrega por la API moderna. Con el handler de arriba registrado no
// debería dispararse; está por si AppKit se queda con el evento.
- (void)application:(NSApplication *)app openURLs:(NSArray<NSURL *> *)urls {
	if ([urls count] > 0) {
		[self recibir:[[urls firstObject] absoluteString]];
	}
}

- (void)applicationDidFinishLaunching:(NSNotification *)aviso {
	self.lanzada = YES;
	if (self.uri != nil) {
		[self cortar];
		return;
	}
	// Abierto a mano (doble clic) no llega ningún link: se espera un momento
	// por si el evento viene atrasado y se sigue.
	[self performSelector:@selector(cortar) withObject:nil afterDelay:self.espera];
}

// Se queda con el PRIMER link. Un segundo clic en "Firmar" mientras el diálogo
// del PIN está abierto llega a este mismo proceso —macOS no lanza otro— y se
// descarta: esa sesión vence sola del lado del servidor.
- (void)recibir:(NSString *)uri {
	if (uri == nil || self.uri != nil) {
		return;
	}
	self.uri = uri;
	if (self.lanzada) {
		[self cortar];
	}
}

- (void)cortar {
	if (!self.corriendo) {
		return;
	}
	self.corriendo = NO;
	[NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(cortar) object:nil];
	[NSApp stop:nil];
	// stop: recién corta al procesar el próximo evento: se le da uno.
	NSEvent *vacio = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
	                                    location:NSZeroPoint
	                               modifierFlags:0
	                                   timestamp:0
	                                windowNumber:0
	                                     context:nil
	                                     subtype:0
	                                       data1:0
	                                       data2:0];
	[NSApp postEvent:vacio atStart:YES];
}

@end

// NSApp guarda su delegate sin retenerlo: esta referencia es la que lo mantiene vivo.
static GDIArranque *gdiArranque = nil;

// Devuelve el link con el que el sistema abrió el programa (lo libera el
// llamador con free) o NULL si se lo abrió sin link.
static char *gdiEsperarURI(double espera) {
	@autoreleasepool {
		gdiPrepararApp();
		gdiArranque = [[GDIArranque alloc] init];
		gdiArranque.espera = espera;
		gdiArranque.corriendo = YES;
		[NSApp setDelegate:gdiArranque];
		[NSApp run];

		NSString *uri = gdiArranque.uri;
		if (uri == nil) {
			return NULL;
		}
		return strdup([uri UTF8String]);
	}
}
*/
import "C"

import (
	"log"
	"runtime"
	"time"
	"unsafe"
)

// esperaDelLink es cuánto se espera el Apple Event después de que la app
// terminó de arrancar. Lanzado por el navegador el link ya llegó para entonces
// y no se espera nada; este margen solo se paga al abrir el programa a mano.
const esperaDelLink = 2 * time.Second

func init() {
	// Ver "El hilo principal" arriba: main tiene que quedar en el hilo
	// principal del proceso, que es el único desde el que AppKit funciona.
	runtime.LockOSThread()
}

// URIDeArranque devuelve el link gdifirma:// con el que macOS abrió el
// programa, o "" si se lo abrió sin ninguno. Bloquea, como mucho, lo que tarda
// la app en arrancar más esperaDelLink.
func URIDeArranque() string {
	c := C.gdiEsperarURI(C.double(esperaDelLink.Seconds()))
	if c == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(c))
	return C.GoString(c)
}

// ShowPINDialog muestra el diálogo del PIN. Bloquea hasta que el funcionario
// acepta o cancela.
func ShowPINDialog(info TokenInfo) (PINResult, error) {
	log.Printf("ShowPINDialog: iniciando (AppKit) — label=%q", info.Label)

	titulo, detalle := textoDelPIN(info)
	cTitulo := C.CString(titulo)
	defer C.free(unsafe.Pointer(cTitulo))
	cDetalle := C.CString(detalle)
	defer C.free(unsafe.Pointer(cDetalle))

	// "Firmar" con el campo vacío no cierra nada en Windows; acá NSAlert se
	// cierra igual, así que se vuelve a mostrar hasta que haya PIN o cancele.
	for {
		c := C.gdiPedirPIN(cTitulo, cDetalle)
		if c == nil {
			log.Println("ShowPINDialog: cancelado")
			return PINResult{Cancelled: true}, ErrCancelled
		}
		pin := C.GoString(c)
		C.free(unsafe.Pointer(c))
		if pin != "" {
			log.Printf("ShowPINDialog: PIN recibido (len=%d)", len(pin))
			return PINResult{PIN: pin}, nil
		}
	}
}

// ShowInfoDialog muestra un diálogo informativo. Bloquea hasta "Aceptar".
func ShowInfoDialog(title, message string) {
	aviso(title, message, false)
}

// ShowErrorDialog muestra un diálogo de error. Bloquea hasta "Aceptar".
func ShowErrorDialog(title, message string) {
	aviso(title, message, true)
}

func aviso(title, message string, esError bool) {
	cTitulo := C.CString(title)
	defer C.free(unsafe.Pointer(cTitulo))
	cMensaje := C.CString(message)
	defer C.free(unsafe.Pointer(cMensaje))

	var flag C.int
	if esError {
		flag = 1
	}
	C.gdiAviso(cTitulo, cMensaje, flag)
}
