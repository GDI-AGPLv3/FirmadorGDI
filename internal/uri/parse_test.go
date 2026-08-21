package uri

import "testing"

const servlet = "https%3A%2F%2Fgdi-backend-dev.fly.dev%2Fdigital-signature%2Fstorage"

func uriSign() string {
	return "gdifirma://sign?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
}

func uriBatch() string {
	return "gdifirma://batch?ver=1_1&manifest=MANABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
}

// El flujo de a uno NO se toca: hay municipios firmando así.
func TestSignSigueAndando(t *testing.T) {
	p, err := Parse(uriSign())
	if err != nil {
		t.Fatalf("no parseó una URI de firma normal: %v", err)
	}
	if p.Op != OpSign {
		t.Errorf("Op = %q, se esperaba sign", p.Op)
	}
	if p.FileID != "DATAABC" || p.SessionID != "SESABC" {
		t.Errorf("parseo incorrecto: fileid=%q id=%q", p.FileID, p.SessionID)
	}
}

// Chrome a veces agrega una barra después del host.
func TestSignConBarraDeChrome(t *testing.T) {
	raw := "gdifirma://sign/?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("la barra de Chrome rompió el parseo: %v", err)
	}
	if p.Op != OpSign {
		t.Errorf("Op = %q, se esperaba sign", p.Op)
	}
}

func TestBatchSeReconoce(t *testing.T) {
	p, err := Parse(uriBatch())
	if err != nil {
		t.Fatalf("no parseó una URI de tanda: %v", err)
	}
	if p.Op != OpBatch {
		t.Errorf("Op = %q, se esperaba batch", p.Op)
	}
	if p.Manifest != "MANABC" {
		t.Errorf("manifest = %q", p.Manifest)
	}
	if p.SessionID != "BATABC" {
		t.Errorf("id de la tanda = %q", p.SessionID)
	}
}

// Cada operación exige lo suyo: sin manifiesto no hay tanda que firmar.
func TestBatchSinManifiestoFalla(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó una tanda sin manifiesto")
	}
}

// Y una firma de a una sin fileid tampoco: el mensaje de error tiene que
// seguir siendo el de siempre para no confundir a quien lea el log.
func TestSignSinFileIDFalla(t *testing.T) {
	raw := "gdifirma://sign?ver=1_0&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("aceptó una firma sin fileid")
	}
	if got := err.Error(); got != "falta parámetro 'fileid'" {
		t.Errorf("mensaje inesperado: %q", got)
	}
}

func TestOperacionDesconocida(t *testing.T) {
	raw := "gdifirma://cualquiera?ver=1_0&fileid=DATAABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=SESABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó una operación que no existe")
	}
}

// Los identificadores son la ÚNICA credencial del endpoint público que usa
// este programa. Alfanuméricos puros, sin excepciones.
func TestManifiestoNoAlfanumericoFalla(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&manifest=MAN-ABC&rtservlet=" + servlet +
		"&stservlet=" + servlet + "&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó un manifiesto con guiones")
	}
}

func TestServletTieneQueSerHTTPS(t *testing.T) {
	raw := "gdifirma://batch?ver=1_1&manifest=MANABC" +
		"&rtservlet=http%3A%2F%2Fmalo.example.com&stservlet=" + servlet +
		"&id=BATABC&keystore=PKCS11"
	if _, err := Parse(raw); err == nil {
		t.Fatal("aceptó un servlet en HTTP plano")
	}
}
