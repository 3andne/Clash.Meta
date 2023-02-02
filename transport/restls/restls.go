package restls

import (
	"crypto/sha1"
	"fmt"
	"net"

	tls "github.com/3andne/restls-client-go"
)

const (
	Mode string = "restls"
)

var (
	DefaultALPN = []string{"h2", "http/1.1"}
)

// Restls
type Restls struct {
	net.Conn
}

func (r *Restls) Read(b []byte) (int, error) {
	return r.Conn.Read(b)
}

func (r *Restls) Write(b []byte) (int, error) {
	return r.Conn.Write(b)
}

var curveIDMap = map[string]tls.CurveID{
	"CurveP256": tls.CurveP256,
	"CurveP384": tls.CurveP384,
	"CurveP521": tls.CurveP521,
	"X25519":    tls.X25519,
}

var versionMap = map[string]uint8{
	"tls12": tls.TLS12Hint,
	"tls13": tls.TLS13Hint,
}

// NewRestls return a Restls Connection
func NewRestls(conn net.Conn, serverName string, password string, versionHintString string, CurveIDHintString string) (net.Conn, error) {
	password_byte := sha1.New()
	password_byte.Write([]byte(password))
	versionHint, ok := versionMap[versionHintString]
	if !ok {
		return nil, fmt.Errorf("invalid version hint: should be either tls12 or tls13")
	}
	curveIDHint, ok := curveIDMap[CurveIDHintString]
	if !ok && versionHint != tls.TLS13Hint {
		return nil, fmt.Errorf("you must provide a curveIDHint for restls 1.2")
	}

	return &Restls{
		Conn: tls.Client(conn, &tls.Config{RestlsSecret: password_byte.Sum(nil), CurveIDHint: curveIDHint, VersionHint: versionHint, ServerName: serverName}),
	}, nil
}
