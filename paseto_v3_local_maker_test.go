package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPasetoV3Local(t *testing.T) {
	// Valid 32-byte hex key for testing
	symmetricKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("NewPasetoV3Local", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)
		require.NotNil(t, maker)

		// Test invalid hex string (this error occurs first)
		_, err = NewPasetoV3Local("too_short")
		require.Error(t, err)
		require.Equal(t, "invalid symmetric key hex", err.Error())

		// Test invalid key length (using valid hex but wrong length)
		_, err = NewPasetoV3Local("0123456789abcdef") // valid hex but too short
		require.Error(t, err)
		require.Equal(t, "symmetric key must be 32 bytes long", err.Error())
	})

	t.Run("CreateAndVerifyToken", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)

		username := "test_user"
		duration := time.Minute

		// Create token
		token, payload, err := maker.CreateToken(username, duration)
		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotNil(t, payload)

		// Verify token
		verifiedPayload, err := maker.VerifyToken(token)
		require.NoError(t, err)
		require.NotNil(t, verifiedPayload)

		// Check payload fields
		require.Equal(t, username, verifiedPayload.Username)
		require.Equal(t, payload.ID, verifiedPayload.ID)
		require.WithinDuration(t, payload.IssuedAt, verifiedPayload.IssuedAt, time.Second)
		require.WithinDuration(t, payload.ExpiredAt, verifiedPayload.ExpiredAt, time.Second)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)

		// Create token with -1 minute duration (already expired)
		token, payload, err := maker.CreateToken("test_user", -time.Minute)
		require.NoError(t, err)
		require.NotNil(t, payload)

		// Verify should fail
		verifiedPayload, err := maker.VerifyToken(token)
		require.Error(t, err)
		require.Nil(t, verifiedPayload)
		require.Contains(t, err.Error(), "could not parse payload: this token has expired")
	})

	t.Run("InvalidToken", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)

		// Try to verify invalid token
		verifiedPayload, err := maker.VerifyToken("invalid.token.format")
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not parse payload")
		require.Nil(t, verifiedPayload)

		// Try to verify empty token
		verifiedPayload, err = maker.VerifyToken("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not parse payload")
		require.Nil(t, verifiedPayload)
	})

	t.Run("WrongKey", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)

		// Create token
		token, _, err := maker.CreateToken("test_user", time.Minute)
		require.NoError(t, err)

		// Create new maker with different key
		differentKey := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		wrongMaker, err := NewPasetoV3Local(differentKey)
		require.NoError(t, err)

		// Verify should fail because symmetric key doesn't match
		verifiedPayload, err := wrongMaker.VerifyToken(token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not parse payload")
		require.Nil(t, verifiedPayload)
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		maker, err := NewPasetoV3Local(symmetricKey)
		require.NoError(t, err)

		// Create token
		token, _, err := maker.CreateToken("test_user", time.Minute)
		require.NoError(t, err)

		// Tamper with the token to make UUID invalid
		tamperedToken := token + "tampered"

		// Verify should fail because token is tampered
		verifiedPayload, err := maker.VerifyToken(tamperedToken)
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not parse payload")
		require.Nil(t, verifiedPayload)
	})
}
