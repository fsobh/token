package demo

import (
	"fmt"
	"github.com/fsobh/token"
	"golang.org/x/crypto/ed25519"
	"time"
)

func DemoJWTSym(symmetricKey string) {

	jwtMakerSymmetric, err := token.NewJWTMaker(symmetricKey)

	if err != nil {
		_ = fmt.Errorf("Cannot create JWT jwtMakerSymmetric: %v\n", err)
	}

	jwtTokenSymmetric, jwtPayloadSymmetric, err := jwtMakerSymmetric.CreateToken("charlie", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      jwtTokenSymmetric,
		"payload":    jwtPayloadSymmetric,
		"expiration": jwtPayloadSymmetric.ExpiredAt,
	}))

	// Verify the token
	jwtVerifiedPayloadSymmetric, err := jwtMakerSymmetric.VerifyToken(jwtTokenSymmetric)
	if err != nil {
		_ = fmt.Errorf("failed to verify token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Payload (JSON):")
	fmt.Println(toJSON(jwtVerifiedPayloadSymmetric))

}
func DemoJWTASym(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) {

	jwtMakerAsymmetric, err := token.NewAsymJWTMaker(privateKey, publicKey)

	if err != nil {
		_ = fmt.Errorf("Cannot create JWT jwtMakerAsymmetric: %v\n", err)
	}

	jwtTokenAsymmetric, jwtPayloadAsymmetric, err := jwtMakerAsymmetric.CreateToken("charlie", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      jwtTokenAsymmetric,
		"payload":    jwtPayloadAsymmetric,
		"expiration": jwtPayloadAsymmetric.ExpiredAt,
	}))

	// Verify the token
	jwtVerifiedPayloadAsymmetric, err := jwtMakerAsymmetric.VerifyToken(jwtTokenAsymmetric)
	if err != nil {
		_ = fmt.Errorf("failed to verify token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Payload (JSON):")
	fmt.Println(toJSON(jwtVerifiedPayloadAsymmetric))

}
