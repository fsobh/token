package main

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
	"github.com/fsobh/token"
	"time"
)

func main() {

	// Paseto V2 PUBLIC
	privateKey := paseto.NewV2AsymmetricSecretKey()
	publicKey := privateKey.Public()

	// Export keys as hex strings
	privateKeyString := privateKey.ExportHex()
	publicKeyString := publicKey.ExportHex()

	fmt.Println("Private Key (Hex):", privateKeyString)
	fmt.Println("Public Key (Hex):", publicKeyString)

	maker, err := token.NewPasetoV2Public(privateKeyString, publicKeyString)

	if err != nil {
		fmt.Println(err)
	}

	accessToken, payload, err := maker.CreateToken("username", time.Duration(10)*time.Minute)

	fmt.Println(accessToken)
	fmt.Println(payload)

	verified, err := maker.VerifyToken(accessToken)

	fmt.Println(verified)
}
