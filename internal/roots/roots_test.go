package roots

import (
	"crypto/x509"
	"testing"
)

func TestTheBundleParsesAndIsNotEmpty(t *testing.T) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no certificate parsed")
	}
	if n := len(pool.Subjects()); n < 100 { //nolint:staticcheck // a count, not a trust decision
		t.Errorf("%d certificates", n)
	}
	Ensure()
	Ensure() // twice must be safe: SetFallbackRoots panics on a second call
}
