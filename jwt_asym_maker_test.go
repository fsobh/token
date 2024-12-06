package token

import (
	"crypto/rand"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAsymJWTMaker(t *testing.T) {
	// Generate valid Ed25519 key pair for testing
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("NewAsymJWTMaker", func(t *testing.T) {
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
		require.NoError(t, err)
		require.NotNil(t, maker)
	})

	t.Run("CreateAndVerifyToken", func(t *testing.T) {
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
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
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
		require.NoError(t, err)

		// Create token with -1 minute duration (already expired)
		token, payload, err := maker.CreateToken("test_user", -time.Minute)
		require.NoError(t, err)
		require.NotNil(t, payload)

		// Verify should fail
		verifiedPayload, err := maker.VerifyToken(token)
		require.Error(t, err)
		require.Equal(t, ErrExpiredToken, err)
		require.Nil(t, verifiedPayload)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
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
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
		require.NoError(t, err)

		// Create token
		token, _, err := maker.CreateToken("test_user", time.Minute)
		require.NoError(t, err)

		// Create new key pair
		wrongPublicKey, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Create new maker with different public key
		wrongMaker, err := NewAsymJWTMaker(wrongPrivateKey, wrongPublicKey)
		require.NoError(t, err)

		// Verify should fail because public key doesn't match
		verifiedPayload, err := wrongMaker.VerifyToken(token)
		require.Error(t, err)
		require.Equal(t, ErrInvalidToken, err)
		require.Nil(t, verifiedPayload)
	})

	t.Run("InvalidSigningMethod", func(t *testing.T) {
		maker, err := NewAsymJWTMaker(privateKey, publicKey)
		require.NoError(t, err)

		// Create token with wrong signing method (this simulates an attack)
		payload, err := NewPayload("test_user", time.Minute)
		require.NoError(t, err)

		token := createTokenWithWrongSigningMethod(payload)

		// Verify should fail because of wrong signing method
		verifiedPayload, err := maker.VerifyToken(token)
		require.Error(t, err)
		require.Equal(t, ErrExpiredToken, err)
		require.Nil(t, verifiedPayload)
	})
}

// Helper function to create a token with wrong signing method
func createTokenWithWrongSigningMethod(payload *Payload) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	signedToken, _ := token.SignedString([]byte("some-secret-key"))
	return signedToken
}
