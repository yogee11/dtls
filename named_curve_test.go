package dtls

import "testing"

func TestNamedCurevFromString(t *testing.T) {
	var tests = []struct {
		s    string
		res  namedCurve
		fail bool
	}{
		{"p256", namedCurveP256, false},
		{"p-256", namedCurveP256, false},
		{"secp256", namedCurveP256, false},
		{"secp256r1", namedCurveP256, false},
		{"p384", namedCurveP384, false},
		{"p-384", namedCurveP384, false},
		{"secp384", namedCurveP384, false},
		{"secp384r1", namedCurveP384, false},
		{"25519", namedCurveX25519, false},
		{"x25519", namedCurveX25519, false},
		{"curve25519", namedCurveX25519, false},
		{"bonkers", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			res, err := namedCurveFromString(tt.s)
			if err == nil && tt.fail {
				t.Errorf("expected '%s' to be valid", tt.s)
			}
			if err != nil && !tt.fail {
				t.Errorf("expected '%s' to be invalid", tt.s)
			}
			if res != tt.res {
				t.Errorf("excepted %v, got %v", tt.res, res)
			}
		})
	}
}
