package ui

// Ventana de progreso de la firma en tanda (GDI-167).
//
// Antes de esto el firmador no mostraba NADA mientras trabajaba: con un solo
// documento la ventana del PIN se cerraba y en un segundo estaba listo. Con
// cinco, el usuario queda mirando la nada durante varios segundos sin saber si
// el programa se colgó — y el instinto en ese momento es cerrarlo, que es
// justo lo que no tiene que hacer.
//
// Implementación deliberadamente boba: se escribe el avance en el log y, en
// Windows, se actualiza el título de una ventana liviana. No hay barra
// animada ni ventana modal: una tanda son 5 documentos, no 500.

import (
	"log"
	"sync"
)

// Progress informa en qué documento de la tanda va la firma.
type Progress struct {
	mu    sync.Mutex
	total int
	sink  func(actual, total int)
}

// NewProgress crea el indicador. Si total <= 1 no muestra nada: es una firma
// de a una y no hay nada que informar.
func NewProgress(total int) *Progress {
	p := &Progress{total: total}
	if total > 1 {
		p.sink = mostrarProgreso
	}
	return p
}

// Update informa que se está firmando el documento `actual` de `total`.
func (p *Progress) Update(actual, total int) {
	if p == nil || p.sink == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sink(actual, total)
}

// Close cierra el indicador. Seguro de llamar más de una vez.
func (p *Progress) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sink = nil
}

func mostrarProgreso(actual, total int) {
	// El log es la única herramienta de soporte que existe para este programa:
	// que el avance quede ahí no es decorativo.
	log.Printf("Firmando %d de %d…", actual, total)
	tituloDeVentana(actual, total)
}
