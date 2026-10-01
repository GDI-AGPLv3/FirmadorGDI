package pkcs11

import (
	"errors"
	"strings"
	"testing"

	p11 "github.com/miekg/pkcs11"
)

// driverFalso es un middleware de mentira. Con hardware esto no se puede
// probar sin dos tokens de marcas distintas enchufados por turnos; lo que sí se
// puede fijar acá es la DECISIÓN: a qué driver se le pregunta, con cuál se
// queda y cuáles suelta.
type driverFalso struct {
	nombre string

	noInicializa error     // Initialize falla
	slots        []uint    // tokens que ve
	noAbre       error     // OpenSession falla
	sinInfo      error     // GetTokenInfo falla
	registro     *[]string // llamadas, en orden, de todos los drivers
}

func (d *driverFalso) anotar(que string) { *d.registro = append(*d.registro, d.nombre+"."+que) }

func (d *driverFalso) Initialize() error {
	d.anotar("Initialize")
	return d.noInicializa
}
func (d *driverFalso) Finalize() error { d.anotar("Finalize"); return nil }
func (d *driverFalso) Destroy()        { d.anotar("Destroy") }
func (d *driverFalso) GetSlotList(bool) ([]uint, error) {
	d.anotar("GetSlotList")
	return d.slots, nil
}
func (d *driverFalso) GetTokenInfo(uint) (p11.TokenInfo, error) {
	return p11.TokenInfo{Label: "token de " + d.nombre}, d.sinInfo
}
func (d *driverFalso) OpenSession(uint, uint) (p11.SessionHandle, error) {
	return p11.SessionHandle(7), d.noAbre
}

// maquina arma una PC con esos drivers instalados. Lo que no está en el mapa
// "no está instalado": cargar devuelve nil, igual que p11.New.
func maquina(registro *[]string, instalados ...*driverFalso) func(string) modulo {
	porNombre := map[string]*driverFalso{}
	for _, d := range instalados {
		d.registro = registro
		porNombre[d.nombre] = d
	}
	return func(ruta string) modulo {
		d, ok := porNombre[ruta]
		if !ok {
			return nil
		}
		return d
	}
}

var lista = []string{"feitian", "safenet", "opensc"}

func contiene(registro []string, llamada string) bool {
	for _, r := range registro {
		if r == llamada {
			return true
		}
	}
	return false
}

// EL caso que se reportó: dos middlewares instalados y enchufado el token del
// SEGUNDO. Hasta la 1.7.0 se quedaba con el de Feitian —que carga bien y no ve
// nada— y cortaba con "no hay tokens conectados".
func TestConDosDriversSeUsaElQueVeElToken(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: "feitian"},                   // instalado, sin token
		&driverFalso{nombre: "safenet", slots: []uint{3}}, // el del token enchufado
	)

	e, err := elegirDriver(lista, cargar)
	if err != nil {
		t.Fatalf("hay un token enchufado y un driver que lo ve, pero falló: %v", err)
	}
	if e.ruta != "safenet" {
		t.Fatalf("se eligió %q y el token es del driver safenet", e.ruta)
	}
	if e.info.Label != "token de safenet" {
		t.Errorf("la info del token salió de otro driver: %q", e.info.Label)
	}

	// El que no sirvió se cierra ANTES de usar el otro: dos middlewares
	// inicializados sobre el mismo lector se pisan.
	for _, llamada := range []string{"feitian.Finalize", "feitian.Destroy"} {
		if !contiene(registro, llamada) {
			t.Errorf("no se llamó a %s: el driver descartado quedó cargado", llamada)
		}
	}
	// Y el elegido NO se cierra: con él se va a firmar.
	for _, llamada := range []string{"safenet.Finalize", "safenet.Destroy"} {
		if contiene(registro, llamada) {
			t.Errorf("se llamó a %s sobre el driver elegido", llamada)
		}
	}
}

// El orden de la lista sigue siendo el desempate, y no se carga de más: si el
// primero ya tiene el token, a los otros ni se los toca.
func TestSiElPrimeroVeElTokenNoSeCarganLosDemas(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: "feitian", slots: []uint{1}},
		&driverFalso{nombre: "safenet", slots: []uint{1}},
	)

	e, err := elegirDriver(lista, cargar)
	if err != nil {
		t.Fatal(err)
	}
	if e.ruta != "feitian" {
		t.Errorf("se eligió %q; con los dos viendo un token gana el primero de la lista", e.ruta)
	}
	if contiene(registro, "safenet.Initialize") {
		t.Error("se inicializó un segundo driver sin necesidad")
	}
}

func TestSinNingunDriverInstalado(t *testing.T) {
	var registro []string
	_, err := elegirDriver(lista, maquina(&registro))
	if !errors.Is(err, ErrSinDriver) {
		t.Fatalf("sin drivers se esperaba ErrSinDriver y vino: %v", err)
	}
	// La documentación de usuario cita este texto tal cual.
	if err.Error() != "no se encontró driver PKCS#11 compatible" {
		t.Errorf("cambió el mensaje que cita la documentación: %q", err.Error())
	}
}

// Con drivers instalados y ningún token enchufado el error es OTRO: mandar al
// funcionario a instalar un controlador que ya tiene es hacerle perder la
// mañana. Y dice qué se probó, que es lo primero que pregunta soporte.
func TestConDriversPeroSinTokenElErrorLoDice(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: `C:\Windows\System32\eps2003csp11.dll`},
		&driverFalso{nombre: "/usr/local/lib/libeTPkcs11.dylib"},
	)
	rutas := []string{`C:\Windows\System32\eps2003csp11.dll`, "/usr/local/lib/libeTPkcs11.dylib"}

	_, err := elegirDriver(rutas, cargar)
	if !errors.Is(err, ErrSinToken) {
		t.Fatalf("se esperaba ErrSinToken y vino: %v", err)
	}
	if errors.Is(err, ErrSinDriver) {
		t.Error("hay drivers instalados: no puede decir que falta el driver")
	}
	for _, nombre := range []string{"eps2003csp11.dll", "libeTPkcs11.dylib"} {
		if !strings.Contains(err.Error(), nombre) {
			t.Errorf("el error no nombra el driver %s que se probó: %q", nombre, err.Error())
		}
	}
	if strings.Contains(err.Error(), "System32") {
		t.Errorf("el error muestra la ruta completa en vez del nombre: %q", err.Error())
	}

	// Ninguno queda cargado.
	for _, ruta := range rutas {
		if !contiene(registro, ruta+".Finalize") || !contiene(registro, ruta+".Destroy") {
			t.Errorf("el driver %s quedó sin cerrar", ruta)
		}
	}
}

// Un driver que está en disco pero no inicializa (instalación rota, servicio
// del lector caído) no frena la búsqueda. Y no se le llama Finalize: no llegó
// a inicializarse.
func TestUnDriverQueNoInicializaNoFrenaLaBusqueda(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: "feitian", noInicializa: errors.New("CKR_GENERAL_ERROR")},
		&driverFalso{nombre: "safenet", slots: []uint{1}},
	)

	e, err := elegirDriver(lista, cargar)
	if err != nil {
		t.Fatalf("el segundo driver servía y falló igual: %v", err)
	}
	if e.ruta != "safenet" {
		t.Errorf("se eligió %q", e.ruta)
	}
	if !contiene(registro, "feitian.Destroy") {
		t.Error("el driver que no inicializó quedó cargado")
	}
	if contiene(registro, "feitian.Finalize") {
		t.Error("se llamó a Finalize sobre un driver que nunca inicializó")
	}
}

// OpenSC es genérico: a veces "ve" un token de otra marca y no lo puede abrir.
// Eso no puede tapar al driver del fabricante que viene después en la lista.
func TestUnDriverQueVeElTokenYNoLoAbreNoTapaAlQueSi(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: "feitian", slots: []uint{1}, noAbre: errors.New("CKR_TOKEN_NOT_RECOGNIZED")},
		&driverFalso{nombre: "safenet", slots: []uint{1}},
	)

	e, err := elegirDriver(lista, cargar)
	if err != nil {
		t.Fatalf("había un driver que abría el token y falló: %v", err)
	}
	if e.ruta != "safenet" {
		t.Errorf("se eligió %q", e.ruta)
	}
}

// Si el ÚNICO driver que ve el token no lo puede abrir, el error es ese y no
// "no hay tokens conectados": el token está, el problema es otro.
func TestSiNadiePuedeAbrirElTokenElErrorNoEsQueFalta(t *testing.T) {
	var registro []string
	cargar := maquina(&registro,
		&driverFalso{nombre: "feitian"},
		&driverFalso{nombre: "safenet", slots: []uint{1}, noAbre: errors.New("CKR_TOKEN_NOT_RECOGNIZED")},
	)

	_, err := elegirDriver(lista, cargar)
	if err == nil {
		t.Fatal("no se pudo abrir ningún token y no hubo error")
	}
	if errors.Is(err, ErrSinToken) || errors.Is(err, ErrSinDriver) {
		t.Errorf("el token estaba conectado; el error tiene que ser el de apertura y vino: %v", err)
	}
	if !strings.Contains(err.Error(), "CKR_TOKEN_NOT_RECOGNIZED") || !strings.Contains(err.Error(), "safenet") {
		t.Errorf("el error no dice qué falló ni con qué driver: %q", err.Error())
	}
}
