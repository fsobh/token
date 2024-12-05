package token

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPasetoV2Local(t *testing.T) {
	testCases := []struct {
		name            string
		symmetricKeyHex string
		wantErr         bool
	}{
		{
			name:            "Valid Key",
			symmetricKeyHex: "bc11fab585bca18ad287c5a5c3070153d13f3e8d52a50180a93ca3072f0262a1",
			wantErr:         false,
		},
		{
			name:            "Invalid Hex Key",
			symmetricKeyHex: "not a valid hex",
			wantErr:         true,
		},
		{
			name:            "Invalid Key Length",
			symmetricKeyHex: "00112233",
			wantErr:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPasetoV2Local(tc.symmetricKeyHex)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
