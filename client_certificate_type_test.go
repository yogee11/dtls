package dtls

import "testing"

func TestClientCertificateTypeFromString(t *testing.T) {
	var tests = []struct {
		s    string
		fail bool
	}{
		{"rsa", false},
		{"ecdsa", false},
		{"bonkers", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			_, err := clientCertificateTypeFromString(tt.s)
			if err == nil && tt.fail {
				t.Errorf("expected '%s' to be valid", tt.s)
			}
			if err != nil && !tt.fail {
				t.Errorf("expected '%s' to be invalid", tt.s)
			}
		})
	}
}
