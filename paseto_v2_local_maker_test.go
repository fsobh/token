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

func TestCreateAndVerifyToken(t *testing.T) {
	symmetricKey := "bc11fab585bca18ad287c5a5c3070153d13f3e8d52a50180a93ca3072f0262a1"
	maker, _ := NewPasetoV2Local(symmetricKey)

	// testing for valid username and duration
	testCases := []struct {
		name     string
		username string
		duration time.Duration
		hasError bool
	}{
		{name: "Valid test", username: "testUser", duration: 1 * time.Hour, hasError: false},
		{name: "Empty username test", username: "", duration: 1 * time.Hour, hasError: true},
		{name: "Negative duration test", username: "testUser", duration: -1 * time.Hour, hasError: true},
	}

	for _, testCase := range testCases {
		token, payload, err := maker.CreateToken(testCase.username, testCase.duration)
		if testCase.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)

			// Verify created token
			parsedPayload, err := maker.VerifyToken(token)
			assert.NoError(t, err)
			assert.EqualValues(t, payload, parsedPayload)
		}
	}

	// testing with invalid token
	_, err := maker.VerifyToken("invalid token")
	assert.Error(t, err)

	// testing with expired token
	expiredToken, _, _ := maker.CreateToken("expiredUser", -1*time.Hour)
	_, err = maker.VerifyToken(expiredToken)
	assert.Error(t, err)
}
