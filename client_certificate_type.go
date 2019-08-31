package dtls

import (
	"fmt"
	"strings"
)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
type clientCertificateType byte

const (
	clientCertificateTypeRSASign   clientCertificateType = 1
	clientCertificateTypeECDSASign clientCertificateType = 64
)

var clientCertificateTypes = map[clientCertificateType]bool{
	clientCertificateTypeRSASign:   true,
	clientCertificateTypeECDSASign: true,
}

func clientCertificateTypeFromString(t string) (clientCertificateType, error) {
	t = strings.ToLower(t)

	switch t {
	case "rsa":
		return clientCertificateTypeRSASign, nil
	case "ecdsa":
		return clientCertificateTypeECDSASign, nil
	default:
		return 0, fmt.Errorf("unknown certificate signature type: %s", t)
	}
}
