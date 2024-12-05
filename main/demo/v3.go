package demo

import (
	"fmt"
	"github.com/fsobh/token"
	"time"
)

// DemonstrateV3Local shows how to use PasetoV3Local tokens
func DemonstrateV3Local(symmetricKeyHex string) error {
	// Initialize the maker
	maker, err := token.NewPasetoV3Local(symmetricKeyHex)
	if err != nil {
		return fmt.Errorf("failed to create token maker: %w", err)
	}

	// Create a token
	tokenString, payload, err := maker.CreateToken("bob", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	fmt.Printf("Created token: %s\n", tokenString)

	// Verify the token
	payload, err = maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	fmt.Printf("Verified token payload: %+v\n", payload)

	return nil
}

// DemonstrateV3Public shows how to use PasetoV3Public tokens
func DemonstrateV3Public(privateKeyHex, publicKeyHex string) error {
	// Initialize the maker
	maker, err := token.NewPasetoV3Public(privateKeyHex, publicKeyHex)
	if err != nil {
		return fmt.Errorf("failed to create token maker: %w", err)
	}

	// Create a token
	tokenString, payload, err := maker.CreateToken("dave", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	fmt.Printf("Created token: %s\n", tokenString)

	// Verify the token
	payload, err = maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	fmt.Printf("Verified token payload: %+v\n", payload)

	return nil
}
