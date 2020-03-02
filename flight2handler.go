package dtls

import (
	"bytes"
	"context"
)

func flight2Parse(ctx context.Context, c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) (flightVal, *alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence,
		handshakeCachePullRule{handshakeTypeClientHello, true, true},
	)
	state.handshakeRecvSequence = seq
	if !ok {
		// No valid message received. Keep reading
		return 0, nil, nil
	}
	var clientHello *handshakeMessageClientHello

	// Validate type
	if clientHello, ok = msgs[handshakeTypeClientHello].(*handshakeMessageClientHello); !ok {
		return 0, &alert{alertLevelFatal, alertInternalError}, nil
	}

	if len(clientHello.cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(state.cookie, clientHello.cookie) {
		return 0, &alert{alertLevelFatal, alertAccessDenied}, errCookieMismatch
	}
	return flight4, nil, nil
}

func flight2Generate(c flightConn, state *State, cache *handshakeCache, cfg *handshakeConfig) ([]*packet, *alert, error) {
	return []*packet{
		{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeMessage: &handshakeMessageHelloVerifyRequest{
						version: protocolVersion1_2,
						cookie:  state.cookie,
					},
				},
			},
		},
	}, nil, nil
}
