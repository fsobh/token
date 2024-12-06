package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWTMaker(t *testing.T) {
	maker, err := NewJWTMaker(randomString(32))
	require.NoError(t, err)

	username := "test_user"
	duration := time.Minute

	t.Run("CreateToken", func(t *testing.T) {
		token, payload, err := maker.CreateToken(username, duration)
		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotNil(t, payload)
		require.Equal(t, username, payload.Username)
		require.NotZero(t, payload.ID)
		require.WithinDuration(t, time.Now(), payload.IssuedAt, time.Second)
		require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second)
	})

	t.Run("VerifyToken", func(t *testing.T) {
		token, payload, err := maker.CreateToken(username, duration)
		require.NoError(t, err)

		payload2, err := maker.VerifyToken(token)
		require.NoError(t, err)
		require.NotNil(t, payload2)
		require.Equal(t, payload.ID, payload2.ID)
		require.Equal(t, payload.Username, payload2.Username)
		require.WithinDuration(t, payload.IssuedAt, payload2.IssuedAt, time.Second)
		require.WithinDuration(t, payload.ExpiredAt, payload2.ExpiredAt, time.Second)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		token, payload, err := maker.CreateToken(username, -time.Minute)
		require.NoError(t, err)
		require.NotNil(t, payload)

		payload2, err := maker.VerifyToken(token)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrExpiredToken)
		require.Nil(t, payload2)
	})
}

// Helper function to generate random string
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
} 