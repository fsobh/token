package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPayload(t *testing.T) {
	t.Run("NewPayload", func(t *testing.T) {
		username := "test_user"
		duration := time.Minute

		payload, err := NewPayload(username, duration)
		require.NoError(t, err)
		require.NotNil(t, payload)
		require.Equal(t, username, payload.Username)
		require.NotZero(t, payload.ID)
		require.WithinDuration(t, time.Now(), payload.IssuedAt, time.Second)
		require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second)
	})

	t.Run("Valid", func(t *testing.T) {
		testCases := []struct {
			name        string
			buildPayload func() *Payload
			expectError bool
		}{
			{
				name: "ValidToken",
				buildPayload: func() *Payload {
					payload, _ := NewPayload("user", time.Minute)
					return payload
				},
				expectError: false,
			},
			{
				name: "ExpiredToken",
				buildPayload: func() *Payload {
					payload, _ := NewPayload("user", -time.Minute)
					return payload
				},
				expectError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				payload := tc.buildPayload()
				err := payload.Valid()
				if tc.expectError {
					require.Error(t, err)
					require.ErrorIs(t, err, ErrExpiredToken)
				} else {
					require.NoError(t, err)
				}
			})
		}
	})
} 