// Package roots holds Mozilla's root certificates (scripts/cli/cacert.ts), for a machine with no trust store of its own: a
// minimal container image has none, and a download there would fail. A machine with its own store uses its own: Go consults
// this set only when it finds no system roots.
package roots

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

//go:embed cacert.pem
var pem []byte

// Ensure registers the fallback. Parsing waits until a run reaches for the network.
var Ensure = sync.OnceFunc(func() {
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM(pem) {
		x509.SetFallbackRoots(pool)
	}
})
