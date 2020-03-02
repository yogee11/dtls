package dtls

import (
	"context"
)

// Parse received handshakes and return next flightVal
type flightParser func(context.Context, flightConn, *State, *handshakeCache, *handshakeConfig) (flightVal, *alert, error)

// Generate flights
type flightGenerator func(flightConn, *State, *handshakeCache, *handshakeConfig) ([]*packet, *alert, error)

func (f flightVal) getFlightParser() flightParser {
	switch f {
	case flight0:
		return flight0Parse
	case flight1:
		return flight1Parse
	case flight2:
		return flight2Parse
	case flight3:
		return flight3Parse
	case flight4:
		return flight4Parse
	case flight5:
		return flight5Parse
	case flight6:
		return flight6Parse
	default:
		return nil
	}
}

func (f flightVal) getFlightGenerator() flightGenerator {
	switch f {
	case flight0:
		return flight0Generate
	case flight1:
		return flight1Generate
	case flight2:
		return flight2Generate
	case flight3:
		return flight3Generate
	case flight4:
		return flight4Generate
	case flight5:
		return flight5Generate
	case flight6:
		return flight6Generate
	default:
		return nil
	}
}
