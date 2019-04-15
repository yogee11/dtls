package dtls

import (
	"hash"
)

type cipherSuiteTLSNullWithNullNull struct {
}

func (c cipherSuiteTLSNullWithNullNull) certificateType() clientCertificateType {
	return clientCertificateTypeECDSASign
}

func (c cipherSuiteTLSNullWithNullNull) ID() cipherSuiteID {
	return 0x0
}

func (c cipherSuiteTLSNullWithNullNull) String() string {
	return "TLSNullWithNullNull"
}

func (c cipherSuiteTLSNullWithNullNull) hashFunc() func() hash.Hash {
	return nil
}

func (c *cipherSuiteTLSNullWithNullNull) init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {

	return nil
}

func (c *cipherSuiteTLSNullWithNullNull) encrypt(pkt *recordLayer, raw []byte) ([]byte, error) {
	return raw, nil
}

func (c *cipherSuiteTLSNullWithNullNull) decrypt(raw []byte) ([]byte, error) {
	return raw, nil
}
