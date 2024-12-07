package main

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
	"github.com/fsobh/token/main/demo"
)

func main() {

	// Generate Keys
	privateKeyV2 := paseto.NewV2AsymmetricSecretKey()
	publicKeyV2 := privateKeyV2.Public()

	symmetricKeyV2 := paseto.NewV2SymmetricKey()

	privateKeyV3 := paseto.NewV3AsymmetricSecretKey()
	publicKeyV3 := privateKeyV3.Public()

	symmetricKeyV3 := paseto.NewV3SymmetricKey()

	// convert keys to Hex
	privateKeyStringV2 := privateKeyV2.ExportHex()
	publicKeyStringV2 := publicKeyV2.ExportHex()

	symmetricKeyStringV2 := symmetricKeyV2.ExportHex()

	privateKeyStringV3 := privateKeyV3.ExportHex()
	publicKeyStringV3 := publicKeyV3.ExportHex()

	symmetricKeyStringV3 := symmetricKeyV3.ExportHex()

	//// Demonstrate each token type
	if err := demo.DemonstrateV2Local(symmetricKeyStringV2); err != nil {
		fmt.Printf("V2 Local demo failed: %v\n", err)
	}

	if err := demo.DemonstrateV2Public(privateKeyStringV2, publicKeyStringV2); err != nil {
		fmt.Printf("V2 Public demo failed: %v\n", err)
	}

	if err := demo.DemonstrateV3Local(symmetricKeyStringV3); err != nil {
		fmt.Printf("V3 Local demo failed: %v\n", err)
	}

	if err := demo.DemonstrateV3Public(privateKeyStringV3, publicKeyStringV3); err != nil {
		fmt.Printf("V3 Public demo failed: %v\n", err)
	}

}
