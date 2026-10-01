package pkcs11

import (
	"errors"
	"fmt"
	"log"
	"strings"

	p11 "github.com/miekg/pkcs11"
)

// Elegir el driver: cuál de los instalados es el del token que está enchufado.
//
// ── Qué pasaba ──────────────────────────────────────────────────────────────
//
// Hasta la 1.7.0 se usaba EL PRIMER driver que cargara, sin mirar si ese
// driver veía algún token. En una máquina con dos middlewares instalados —el de
// Feitian y el de SafeNet, por ejemplo— y un token SafeNet enchufado, el de
// Feitian cargaba sin problema, contestaba "cero tokens" y el programa cortaba
// con "no hay tokens conectados". Al driver de SafeNet, que era el que servía,
// nunca se le preguntaba.
//
// Pasa de verdad: un funcionario que cambió de token, o un área de sistemas que
// instala los dos middlewares en todas las máquinas porque tiene tokens de las
// dos marcas.
//
// ── Qué se hace ahora ───────────────────────────────────────────────────────
//
// Se recorren los drivers en el mismo orden y se usa el primero que tenga un
// token CONECTADO y que se pueda abrir. El orden de KnownDrivers pasa a ser solo
// el desempate (los del fabricante antes que OpenSC, que es genérico y a veces
// "ve" tokens de otras marcas sin poder usarlos).

// ErrSinDriver: en esta máquina no hay ningún driver PKCS#11 de los conocidos.
var ErrSinDriver = errors.New("no se encontró driver PKCS#11 compatible")

// ErrSinToken: hay drivers instalados pero ninguno detecta un token conectado.
var ErrSinToken = errors.New("no hay tokens conectados")

// modulo es lo que se le pide a un driver PKCS#11 para saber si sirve. Lo
// cumple *p11.Ctx (envuelto en ctxModulo); en los tests, un driver de mentira:
// con hardware real esta lógica no se puede probar sin tener dos tokens de
// marcas distintas sobre la mesa.
type modulo interface {
	Initialize() error
	Finalize() error
	Destroy()
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (p11.TokenInfo, error)
	OpenSession(slotID uint, flags uint) (p11.SessionHandle, error)
}

// ctxModulo adapta *p11.Ctx a la interfaz: Initialize es variádico en la
// librería y así no la cumple.
type ctxModulo struct{ *p11.Ctx }

func (c ctxModulo) Initialize() error { return c.Ctx.Initialize() }

// cargarModulo carga la librería del driver. Devuelve nil si no está instalada
// (o no es de la arquitectura de este proceso).
func cargarModulo(ruta string) modulo {
	c := p11.New(ruta)
	if c == nil {
		return nil
	}
	return ctxModulo{c}
}

// eleccion es el driver elegido, con el token ya abierto.
type eleccion struct {
	ruta    string
	mod     modulo
	info    p11.TokenInfo
	session p11.SessionHandle
}

// elegirDriver devuelve el primer driver de `rutas` que tiene un token
// conectado y lo puede abrir. Los que no sirven se cierran antes de probar el
// siguiente: dos middlewares inicializados a la vez sobre el mismo lector se
// pisan.
func elegirDriver(rutas []string, cargar func(ruta string) modulo) (*eleccion, error) {
	var instalados []string // cargaron, pero no dieron un token utilizable
	var falloAlAbrir error  // un driver VIO un token y no lo pudo abrir

	for _, ruta := range rutas {
		m := cargar(ruta)
		if m == nil {
			continue // no está instalado: lo normal para casi todos
		}
		if err := m.Initialize(); err != nil {
			log.Printf("driver %s: está instalado pero no inicializa: %v", ruta, err)
			m.Destroy()
			continue
		}
		instalados = append(instalados, ruta)

		e, err := abrirToken(ruta, m)
		if err == nil {
			log.Printf("driver elegido: %s", ruta)
			return e, nil
		}

		if errors.Is(err, ErrSinToken) {
			log.Printf("driver %s: cargó pero no ve ningún token conectado", ruta)
		} else {
			log.Printf("driver %s: ve un token pero no lo puede abrir: %v", ruta, err)
			falloAlAbrir = fmt.Errorf("%w (driver %s)", err, nombres([]string{ruta}))
		}
		_ = m.Finalize()
		m.Destroy()
	}

	switch {
	case len(instalados) == 0:
		return nil, ErrSinDriver
	case falloAlAbrir != nil:
		// Más útil que "no hay tokens": el token está, el problema es otro.
		return nil, falloAlAbrir
	default:
		return nil, fmt.Errorf(
			"%w: se probaron los controladores instalados (%s) y ninguno detecta un token",
			ErrSinToken, nombres(instalados))
	}
}

// abrirToken abre el primer token que ve ese driver.
func abrirToken(ruta string, m modulo) (*eleccion, error) {
	slots, err := m.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return nil, ErrSinToken
	}

	info, err := m.GetTokenInfo(slots[0])
	if err != nil {
		return nil, fmt.Errorf("GetTokenInfo: %w", err)
	}

	session, err := m.OpenSession(slots[0], p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("OpenSession: %w", err)
	}

	return &eleccion{ruta: ruta, mod: m, info: info, session: session}, nil
}

// nombres deja solo el nombre de archivo de cada driver: es lo que entiende
// alguien de soporte, y la ruta completa ya quedó en el log.
func nombres(rutas []string) string {
	out := make([]string, 0, len(rutas))
	for _, r := range rutas {
		// filepath.Base no sirve para una ruta de Windows leída en otra
		// plataforma; se corta a mano por las dos barras.
		if i := strings.LastIndexAny(r, `/\`); i >= 0 {
			r = r[i+1:]
		}
		out = append(out, r)
	}
	return strings.Join(out, ", ")
}
