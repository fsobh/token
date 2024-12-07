package main

import (
	"aidanwoods.dev/go-paseto"
	"encoding/json"
	"fmt"
	"github.com/fsobh/token"
	"log"

	"time"
)

func toJSON(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal to JSON: %v", err)
	}
	return string(jsonBytes)
}

func main() {

	// ** Paseto V3 Local **

	symmetricKeyV3 := paseto.NewV3SymmetricKey()
	symmetricKeyStringV3 := symmetricKeyV3.ExportHex()

	localMakerV3, err := token.NewPasetoV3Local(symmetricKeyStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 local token maker: %w", err)
	}

	localTokenStringV3, localPayloadV3, err := localMakerV3.CreateToken("bob", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 local token: %w", err)
	}

	fmt.Println("Created Paseto V3 local Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      localTokenStringV3,
		"payload":    localPayloadV3,
		"expiration": localPayloadV3.ExpiredAt,
	}))

	localVerifiedPayloadV3, err := localMakerV3.VerifyToken(localTokenStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V3 local token: %w", err)
	}

	fmt.Println("Verified Paseto V3 local Payload (JSON):")
	fmt.Println(toJSON(localVerifiedPayloadV3))

	// ** Paseto V3 Public **

	privateKeyV3 := paseto.NewV3AsymmetricSecretKey()
	publicKeyV3 := privateKeyV3.Public()

	privateKeyStringV3 := privateKeyV3.ExportHex()
	publicKeyStringV3 := publicKeyV3.ExportHex()

	publicMakerV3, err := token.NewPasetoV3Public(privateKeyStringV3, publicKeyStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 public token maker: %w", err)
	}

	// Create a token
	publicTokenStringV3, publicPayloadV3, err := publicMakerV3.CreateToken("dave", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 public token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Paseto V3 public Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      publicTokenStringV3,
		"payload":    publicPayloadV3,
		"expiration": publicPayloadV3.ExpiredAt,
	}))

	// Verify the token
	publicVerifiedPayloadV3, err := publicMakerV3.VerifyToken(publicTokenStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V3 public token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Paseto V3 public Payload (JSON):")
	fmt.Println(toJSON(publicVerifiedPayloadV3))
}
