package demo

import (
	"fmt"
	"github.com/fsobh/token"
	"time"
)

// DemonstrateV2Public shows how to use PasetoV2Public tokens
func DemonstrateV2Public(privateKeyHex, publicKeyHex string) error {
	// Initialize the maker
	maker, err := token.NewPasetoV2Public(privateKeyHex, publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to create token maker: %w", err)
	}

	// Create a token
	tokenString, payload, err := maker.CreateToken("charlie", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      tokenString,
		"payload":    payload,
		"expiration": payload.ExpiredAt,
	}))

	// Verify the token
	verifiedPayload, err := maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Payload (JSON):")
	fmt.Println(toJSON(verifiedPayload))

	return nil
}

// DemonstrateV2Local shows how to use PasetoV2Local tokens
func DemonstrateV2Local(symmetricKeyHex string) error {
	// Initialize the maker
	maker, err := token.NewPasetoV2Local(symmetricKeyHex)
	if err != nil {
		return fmt.Errorf("failed to create token maker: %w", err)
	}

	// Create a token
	tokenString, payload, err := maker.CreateToken("alice", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      tokenString,
		"payload":    payload,
		"expiration": payload.ExpiredAt,
	}))

	// Verify the token
	verifiedPayload, err := maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Payload (JSON):")
	fmt.Println(toJSON(verifiedPayload))

	return nil
}
