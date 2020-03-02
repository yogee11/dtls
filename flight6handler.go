package dtls

import (
	"context"
)

func flight6Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1,
		handshakeCachePullRule{handshakeTypeFinished, true, false},
	)
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}

	if _, ok = msgs[handshakeTypeFinished].(*handshakeMessageFinished); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	// Other party retransmitted the last flight.
	return flight6, nil, nil
}

func flight6Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &changeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{handshakeTypeClientHello, true, false},
			handshakeCachePullRule{handshakeTypeServerHello, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, false, false},
			handshakeCachePullRule{handshakeTypeServerKeyExchange, false, false},
			handshakeCachePullRule{handshakeTypeCertificateRequest, false, false},
			handshakeCachePullRule{handshakeTypeServerHelloDone, false, false},
			handshakeCachePullRule{handshakeTypeCertificate, true, false},
			handshakeCachePullRule{handshakeTypeClientKeyExchange, true, false},
			handshakeCachePullRule{handshakeTypeCertificateVerify, true, false},
			handshakeCachePullRule{handshakeTypeFinished, true, false},
		)

		var err error
		state.localVerifyData, err = prfVerifyDataServer(state.masterSecret, plainText, state.cipherSuite.hashFunc())
		if err != nil {
			return nil, &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
					epoch:           1,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageFinished{
						verifyData: state.localVerifyData,
					}},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)
	return pkts, nil, nil
}
