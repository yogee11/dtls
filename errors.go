package dtls

import (
	"context"
	"errors"

	"golang.org/x/xerrors"
)

// Typed errors
var (
	ErrConnClosed = errors.New("dtls: conn is closed")

	errBufferTooSmall                    = errors.New("dtls: buffer is too small")
	errClientCertificateRequired         = errors.New("dtls: server required client verification, but got none")
	errClientCertificateNotVerified      = errors.New("dtls: client sent certificate but did not verify it")
	errCertificateVerifyNoCertificate    = errors.New("dtls: client sent certificate verify but we have no certificate to verify")
	errNoCertificates                    = errors.New("dtls: no certificates configured")
	errCipherSuiteNoIntersection         = errors.New("dtls: Client+Server do not support any shared cipher suites")
	errCipherSuiteUnset                  = errors.New("dtls: server hello can not be created without a cipher suite")
	errCompressionMethodUnset            = errors.New("dtls: server hello can not be created without a compression method")
	errContextUnsupported                = errors.New("dtls: context is not supported for ExportKeyingMaterial")
	errCookieMismatch                    = errors.New("dtls: Client+Server cookie does not match")
	errCookieTooLong                     = errors.New("dtls: cookie must not be longer then 255 bytes")
	errDTLSPacketInvalidLength           = errors.New("dtls: packet is too short")
	errHandshakeInProgress               = errors.New("dtls: Handshake is in progress")
	errHandshakeMessageUnset             = errors.New("dtls: handshake message unset, unable to marshal")
	errInvalidCipherSpec                 = errors.New("dtls: cipher spec invalid")
	errInvalidCipherSuite                = errors.New("dtls: invalid or unknown cipher suite")
	errInvalidCompressionMethod          = errors.New("dtls: invalid or unknown compression method")
	errInvalidContentType                = errors.New("dtls: invalid content type")
	errInvalidECDSASignature             = errors.New("dtls: ECDSA signature contained zero or negative values")
	errInvalidEllipticCurveType          = errors.New("dtls: invalid or unknown elliptic curve type")
	errInvalidExtensionType              = errors.New("dtls: invalid extension type")
	errInvalidSNIFormat                  = errors.New("dtls: invalid server name format")
	errInvalidHashAlgorithm              = errors.New("dtls: invalid hash algorithm")
	errInvalidMAC                        = errors.New("dtls: invalid mac")
	errInvalidNamedCurve                 = errors.New("dtls: invalid named curve")
	errInvalidPrivateKey                 = errors.New("dtls: invalid private key type")
	errInvalidSignatureAlgorithm         = errors.New("dtls: invalid signature algorithm")
	errKeySignatureGenerateUnimplemented = errors.New("dtls: Unable to generate key signature, unimplemented")
	errKeySignatureMismatch              = errors.New("dtls: Expected and actual key signature do not match")
	errKeySignatureVerifyUnimplemented   = errors.New("dtls: Unable to verify key signature, unimplemented")
	errLengthMismatch                    = errors.New("dtls: data length and declared length do not match")
	errNilNextConn                       = errors.New("dtls: Conn can not be created with a nil nextConn")
	errNotEnoughRoomForNonce             = errors.New("dtls: Buffer not long enough to contain nonce")
	errNotImplemented                    = errors.New("dtls: feature has not been implemented yet")
	errReservedExportKeyingMaterial      = errors.New("dtls: ExportKeyingMaterial can not be used with a reserved label")
	errSequenceNumberOverflow            = errors.New("dtls: sequence number overflow")
	errServerMustHaveCertificate         = errors.New("dtls: Certificate is mandatory for server")
	errUnableToMarshalFragmented         = errors.New("dtls: unable to marshal fragmented handshakes")
	errVerifyDataMismatch                = errors.New("dtls: Expected and actual verify data does not match")
	errNoConfigProvided                  = errors.New("dtls: No config provided")
	errPSKAndCertificate                 = errors.New("dtls: Certificate and PSK provided")
	errPSKAndIdentityMustBeSetForClient  = errors.New("dtls: PSK and PSK Identity Hint must both be set for client")
	errIdentityNoPSK                     = errors.New("dtls: Identity Hint provided but PSK is nil")
	errNoAvailableCipherSuites           = errors.New("dtls: Connection can not be created, no CipherSuites satisfy this Config")
	errInvalidClientKeyExchange          = errors.New("dtls: Unable to determine if ClientKeyExchange is a public key or PSK Identity")
	errNoSupportedEllipticCurves         = errors.New("dtls: Client requested zero or more elliptic curves that are not supported by the server")
	errRequestedButNoSRTPExtension       = errors.New("dtls: SRTP support was requested but server did not respond with use_srtp extension")
	errClientNoMatchingSRTPProfile       = errors.New("dtls: Server responded with SRTP Profile we do not support")
	errServerNoMatchingSRTPProfile       = errors.New("dtls: Client requested SRTP but we have no matching profiles")
	errServerRequiredButNoClientEMS      = errors.New("dtls: Server requires the Extended Master Secret extension, but the client does not support it")
	errClientRequiredButNoServerEMS      = errors.New("dtls: Client required Extended Master Secret extension, but server does not support it")
	errInvalidCertificate                = errors.New("dtls: No certificate provided")

	// Wrapped errors
	errConnectTimeout = xerrors.Errorf("dtls: The connection timed out during the handshake: %w", context.DeadlineExceeded)
)
