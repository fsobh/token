package main

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
	fmt.Printf("Created token: %s\n", tokenString)

	// Verify the token
	payload, err = maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	fmt.Printf("Verified token payload: %+v\n", payload)

	return nil
}

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
	fmt.Printf("Created token: %s\n", tokenString)

	// Verify the token
	payload, err = maker.VerifyToken(tokenString)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	fmt.Printf("Verified token payload: %+v\n", payload)

	return nil
}
