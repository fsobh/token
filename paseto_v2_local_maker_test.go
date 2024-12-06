package token

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
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
func TestCreateTokenPV2L(t *testing.T) {

	type user struct {
		username string
		duration time.Duration
	}

	testCases := []struct {
		name            string
		symmetricKeyHex string
		user            user
		wantErr         bool
	}{
		{
			name:            "OK",
			symmetricKeyHex: "bc11fab585bca18ad287c5a5c3070153d13f3e8d52a50180a93ca3072f0262a1",
			user: user{
				username: "johndoe",
				duration: 1 * time.Minute,
			},
			wantErr: false,
		},
		{
			name:            "Token Expired",
			symmetricKeyHex: "bc11fab585bca18ad287c5a5c3070153d13f3e8d52a50180a93ca3072f0262a1",
			user: user{
				username: "johndoe",
				duration: -1 * time.Minute,
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPasetoV2Local(tc.symmetricKeyHex)
			if tc.wantErr {

				assert.Error(t, err)
			} else {
				maker, err := NewPasetoV2Local(tc.symmetricKeyHex)

				token, payload, err := maker.CreateToken(tc.user.username, tc.user.duration)

				assert.NoError(t, err)
				assert.NotEmpty(t, token)
				assert.NotEmpty(t, payload)
				assert.Equal(t, tc.user.username, payload.Username)
				assert.Equal(t, tc.user.duration, payload.ExpiredAt.Sub(payload.IssuedAt)) // the ttl should equal the "expired at" time - "issued at" time

				verifiedPayload, err := maker.VerifyToken(token)

				assert.Equal(t, payload.Username, verifiedPayload.Username)
				assert.Equal(t, verifiedPayload.ID, payload.ID)

				assert.NoError(t, err)
			}
		})
	}

}
