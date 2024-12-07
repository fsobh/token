package token

import (
	"aidanwoods.dev/go-paseto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPasetoV2Public(t *testing.T) {
	// Generate valid keys for testing
	privateKey := paseto.NewV2AsymmetricSecretKey()
	publicKey := privateKey.Public()
	
	// Convert keys to hex strings
	privateKeyHex := privateKey.ExportHex()
	publicKeyHex := publicKey.ExportHex()

	t.Run("NewPasetoV2Public", func(t *testing.T) {
		maker, err := NewPasetoV2Public(privateKeyHex, publicKeyHex)
		require.NoError(t, err)
		require.NotNil(t, maker)

		// Test invalid private key
		_, err = NewPasetoV2Public("invalid_private_key", publicKeyHex)
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not initialize private asymmetric key")

		// Test invalid public key
		_, err = NewPasetoV2Public(privateKeyHex, "invalid_public_key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not initialize public asymmetric key")
	})

	t.Run("CreateAndVerifyToken", func(t *testing.T) {
		maker, err := NewPasetoV2Public(privateKeyHex, publicKeyHex)
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
		maker, err := NewPasetoV2Public(privateKeyHex, publicKeyHex)
		require.NoError(t, err)

		// Create token with -1 minute duration (already expired)
		token, payload, err := maker.CreateToken("test_user", -time.Minute)
		require.NoError(t, err)
		require.NotNil(t, payload)

		// Verify should fail
		verifiedPayload, err := maker.VerifyToken(token)
		require.Error(t, err)
		require.Nil(t, verifiedPayload)
		require.Equal(t, ErrInvalidToken, err)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		maker, err := NewPasetoV2Public(privateKeyHex, publicKeyHex)
		require.NoError(t, err)

		// Try to verify invalid token
		verifiedPayload, err := maker.VerifyToken("invalid.token.format")
		require.Error(t, err)
		require.Equal(t, ErrInvalidToken, err)
		require.Nil(t, verifiedPayload)

		// Try to verify empty token
		verifiedPayload, err = maker.VerifyToken("")
		require.Error(t, err)
		require.Equal(t, ErrInvalidToken, err)
		require.Nil(t, verifiedPayload)
	})

	t.Run("WrongPublicKey", func(t *testing.T) {
		maker, err := NewPasetoV2Public(privateKeyHex, publicKeyHex)
		require.NoError(t, err)

		// Create token
		token, _, err := maker.CreateToken("test_user", time.Minute)
		require.NoError(t, err)

		// Create new key pair
		differentPrivateKey := paseto.NewV2AsymmetricSecretKey()
		differentPublicKey := differentPrivateKey.Public()

		// Create new maker with different public key
		wrongMaker, err := NewPasetoV2Public(privateKeyHex, differentPublicKey.ExportHex())
		require.NoError(t, err)

		// Verify should fail because public key doesn't match
		verifiedPayload, err := wrongMaker.VerifyToken(token)
		require.Error(t, err)
		require.Equal(t, ErrInvalidToken, err)
		require.Nil(t, verifiedPayload)
	})
} 