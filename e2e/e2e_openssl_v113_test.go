// +build openssl,go1.13,!js

package e2e

import (
	"testing"
)

func TestPionOpenSSLE2ESimpleED25519(t *testing.T) {
	// TODO(igolaizola): make this work with openssl
	/*
		t.Run("OpenSSLServer", func(t *testing.T) {
			testPionE2ESimpleED25519(t, serverOpenSSL, clientPion)
		})
		t.Run("OpenSSLClient", func(t *testing.T) {
			testPionE2ESimpleED25519(t, serverPion, clientOpenSSL)
		})
	*/
}
