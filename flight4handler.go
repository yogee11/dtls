package dtls

import (
	"context"
	"crypto/x509"
)

func flight4Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence,
		handshakeCachePullRule{handshakeTypeCertificate, true, true},
		handshakeCachePullRule{handshakeTypeClientKeyExchange, true, false},
		handshakeCachePullRule{handshakeTypeCertificateVerify, true, true},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	// Validate type
	var clientKeyExchange *handshakeMessageClientKeyExchange
	if clientKeyExchange, ok = msgs[handshakeTypeClientKeyExchange].(*handshakeMessageClientKeyExchange); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	if h, hasCert := msgs[handshakeTypeCertificate].(*handshakeMessageCertificate); hasCert {
		state.remoteCertificate = h.certificate
	}

	if h, hasCertVerify := msgs[handshakeTypeCertificateVerify].(*handshakeMessageCertificateVerify); hasCertVerify {
		if state.remoteCertificate == nil {
			return 0, &alert{alertLevelFatal, alertNoCertificate}, errCertificateVerifyNoCertificate
		}

		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshakeTypeClientHello, true, false},
			handshakeCachePullRule{handshakeTypeServerHello, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, false, false},
			handshakeCachePullRule{handshakeTypeServerKeyExchange, false, false},
			handshakeCachePullRule{handshakeTypeCertificateRequest, false, false},
			handshakeCachePullRule{handshakeTypeServerHelloDone, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, true, false},
			handshakeCachePullRule{handshakeTypeClientKeyExchange, true, false},
		)

		if err := verifyCertificateVerify(plainText, h.hashAlgorithm, h.signature, state.remoteCertificate); err != nil {
			return 0, &alert{alertLevelFatal, alertBadCertificate}, err
		}
		var chains [][]*x509.Certificate
		var err error
		var verified bool
		if cfg.clientAuth >= VerifyClientCertIfGiven {
			if chains, err = verifyClientCert(state.remoteCertificate, cfg.clientCAs); err != nil {
				return 0, &alert{alertLevelFatal, alertBadCertificate}, err
			}
			verified = true
		}
		if cfg.verifyPeerCertificate != nil {
			if err := cfg.verifyPeerCertificate(state.remoteCertificate, chains); err != nil {
				return 0, &alert{alertLevelFatal, alertBadCertificate}, err
			}
		}
		state.remoteCertificateVerified = verified
	}

	if !state.cipherSuite.isInitialized() {
		serverRandom, err := state.localRandom.Marshal()
		if err != nil {
			return 0, &alert{alertLevelFatal, alertInternalError}, err
		}
		clientRandom, err := state.remoteRandom.Marshal()
		if err != nil {
			return 0, &alert{alertLevelFatal, alertInternalError}, err
		}

		var preMasterSecret []byte
		if cfg.localPSKCallback != nil {
			var psk []byte
			if psk, err = cfg.localPSKCallback(clientKeyExchange.identityHint); err != nil {
				return 0, &alert{alertLevelFatal, alertInternalError}, err
			}

			preMasterSecret = prfPSKPreMasterSecret(psk)
		} else {
			preMasterSecret, err = prfPreMasterSecret(clientKeyExchange.publicKey, state.localKeypair.privateKey, state.localKeypair.curve)
			if err != nil {
				return 0, &alert{alertLevelFatal, alertIllegalParameter}, err
			}
		}

		if state.extendedMasterSecret {
			var sessionHash []byte
			sessionHash, err = cache.sessionHash(state.cipherSuite.hashFunc())
			if err != nil {
				return 0, &alert{alertLevelFatal, alertInternalError}, err
			}

			state.masterSecret, err = prfExtendedMasterSecret(preMasterSecret, sessionHash, state.cipherSuite.hashFunc())
			if err != nil {
				return 0, &alert{alertLevelFatal, alertInternalError}, err
			}
		} else {
			state.masterSecret, err = prfMasterSecret(preMasterSecret, clientRandom, serverRandom, state.cipherSuite.hashFunc())
			if err != nil {
				return 0, &alert{alertLevelFatal, alertInternalError}, err
			}
		}

		if err := state.cipherSuite.init(state.masterSecret, clientRandom, serverRandom, false); err != nil {
			return 0, &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	// Now, encrypted packets can be handled
	if err := c.handleQueuedPackets(ctx); err != nil {
		return 0, &alert{alertLevelFatal, alertInternalError}, err
	}

	seq, msgs, ok = cache.fullPullMap(seq,
		handshakeCachePullRule{handshakeTypeFinished, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	state.handshakeRecvSequence = seq

	if _, ok = msgs[handshakeTypeFinished].(*handshakeMessageFinished); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	switch cfg.clientAuth {
	case RequireAnyClientCert:
		if state.remoteCertificate == nil {
			return 0, &alert{alertLevelFatal, alertNoCertificate}, errClientCertificateRequired
		}
	case VerifyClientCertIfGiven:
		if state.remoteCertificate != nil && !state.remoteCertificateVerified {
			return 0, &alert{alertLevelFatal, alertBadCertificate}, errClientCertificateNotVerified
		}
	case RequireAndVerifyClientCert:
		if state.remoteCertificate == nil {
			return 0, &alert{alertLevelFatal, alertNoCertificate}, errClientCertificateRequired
		}
		if !state.remoteCertificateVerified {
			return 0, &alert{alertLevelFatal, alertBadCertificate}, errClientCertificateNotVerified
		}
	}

	return flight6, nil, nil
}

func flight4Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) {
	extensions := []extension{}
	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.extendedMasterSecret {
		extensions = append(extensions, &extensionUseExtendedMasterSecret{
			supported: true,
		})
	}
	if state.srtpProtectionProfile != 0 {
		extensions = append(extensions, &extensionUseSRTP{
			protectionProfiles: []SRTPProtectionProfile{state.srtpProtectionProfile},
		})
	}
	if cfg.localPSKCallback == nil {
		extensions = append(extensions, []extension{
			&extensionSupportedEllipticCurves{
				ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256, namedCurveP384},
			},
			&extensionSupportedPointFormats{
				pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
			},
		}...)
	}

	var pkts []*packet

	pkts = append(pkts, &packet{
		record: &recordLayer{
			recordLayerHeader: recordLayerHeader{
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				handshakeMessage: &handshakeMessageServerHello{
					version:           protocolVersion1_2,
					random:            state.localRandom,
					cipherSuite:       state.cipherSuite,
					compressionMethod: defaultCompressionMethods[0],
					extensions:        extensions,
				}},
		},
	})

	if cfg.localPSKCallback == nil {
		certificate, err := cfg.getCertificate(cfg.serverName)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		pkts = append(pkts, &packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageCertificate{
						certificate: certificate.Certificate,
					}},
			},
		})

		serverRandom, err := state.localRandom.Marshal()
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
		clientRandom, err := state.remoteRandom.Marshal()
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}

		signature, err := generateKeySignature(clientRandom, serverRandom, state.localKeypair.publicKey, state.namedCurve, certificate.PrivateKey, hashAlgorithmSHA256)
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
		state.localKeySignature = signature

		pkts = append(pkts, &packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageServerKeyExchange{
						ellipticCurveType:  ellipticCurveTypeNamedCurve,
						namedCurve:         state.namedCurve,
						publicKey:          state.localKeypair.publicKey,
						hashAlgorithm:      hashAlgorithmSHA256,
						signatureAlgorithm: signatureAlgorithmECDSA,
						signature:          state.localKeySignature,
					}},
			},
		})

		if cfg.clientAuth > NoClientCert {
			pkts = append(pkts, &packet{
				record: &recordLayer{
					recordLayerHeader: recordLayerHeader{
						protocolVersion: protocolVersion1_2,
					},
					content: &handshake{
						handshakeMessage: &handshakeMessageCertificateRequest{
							certificateTypes: []clientCertificateType{clientCertificateTypeRSASign, clientCertificateTypeECDSASign},
							signatureHashAlgorithms: []signatureHashAlgorithm{
								{hashAlgorithmSHA256, signatureAlgorithmRSA},
								{hashAlgorithmSHA384, signatureAlgorithmRSA},
								{hashAlgorithmSHA512, signatureAlgorithmRSA},
								{hashAlgorithmSHA256, signatureAlgorithmECDSA},
								{hashAlgorithmSHA384, signatureAlgorithmECDSA},
								{hashAlgorithmSHA512, signatureAlgorithmECDSA},
							},
						},
					},
				},
			})
		}
	} else if cfg.localPSKIdentityHint != nil {
		// To help the client in selecting which identity to use, the server
		// can provide a "PSK identity hint" in the ServerKeyExchange message.
		// If no hint is provided, the ServerKeyExchange message is omitted.
		//
		// https://tools.ietf.org/html/rfc4279#section-2
		pkts = append(pkts, &packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageServerKeyExchange{
						identityHint: cfg.localPSKIdentityHint,
					}},
			},
		})
	}

	pkts = append(pkts, &packet{
		record: &recordLayer{
			recordLayerHeader: recordLayerHeader{
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				handshakeMessage: &handshakeMessageServerHelloDone{},
			},
		},
	})

	return pkts, nil, nil
}
