# Authentication token module for Golang

![Coverage](./coverage.svg)

A Golang module for generating & verifying various types of authentication tokens seamlessly using [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) or [PASETO](https://paseto.io/).

## Features
- ### Multiple token types support:
    - #### JWT (Symmetric & Asymmetric)
    - #### PASETO V2 (Local & Public)
    - #### PASETO V3 (Local & Public)
- Secure key handling
- Built-in token expiration
- Payload validation
- Easy-to-use interface

---

## Installation
Get started by installing the package:

```sh 
go get github.com/fsobh/token
```

---

## Usage

```go
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

  // Generate Keys
  /*
     Never paste your credentials directly in the code for safety reasons
     Recommended : Store these in environment variables using [viper](https://github.com/spf13/viper)
  */
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

  // ** Paseto V2 Local **
  localMakerV2, err := token.NewPasetoV2Local(symmetricKeyStringV2)
  if err != nil {
    _ = fmt.Errorf("failed to create Paseto V2 local token maker: %w", err)
  }

  localTokenStringV2, localPayloadV2, err := localMakerV2.CreateToken("alice", 24*time.Hour)
  if err != nil {
    _ = fmt.Errorf("failed to create Paseto V2 local token: %w", err)
  }

  fmt.Println("Created Paseto V2 local Token (JSON):")
  fmt.Println(toJSON(map[string]interface{}{
    "token":      localTokenStringV2,
    "payload":    localPayloadV2,
    "expiration": localPayloadV2.ExpiredAt,
  }))

  // Verify the token
  verifiedPayload, err := localMakerV2.VerifyToken(localTokenStringV2)
  if err != nil {
    _ = fmt.Errorf("failed to verify Paseto V2 local token: %w", err)
  }

  // Display verified payload in JSON
  fmt.Println("Verified Paseto V2 local Payload (JSON):")
  fmt.Println(toJSON(verifiedPayload))

  // ** Paseto V2 Public **
  publicMakerV2, err := token.NewPasetoV2Public(privateKeyStringV2, publicKeyStringV2)
  if err != nil {
    _ = fmt.Errorf("failed to create Paseto V2 public token maker: %w", err)
  }

  // Create a token
  publicTokenStringV2, publicPayloadV2, err := publicMakerV2.CreateToken("charlie", 24*time.Hour)
  if err != nil {
    _ = fmt.Errorf("failed to create Paseto V2 public token: %w", err)
  }

  // Display token and payload in JSON
  fmt.Println("Created Paseto V2 public Token (JSON):")
  fmt.Println(toJSON(map[string]interface{}{
    "token":      publicTokenStringV2,
    "payload":    publicPayloadV2,
    "expiration": publicPayloadV2.ExpiredAt,
  }))

  // Verify the token
  publicVerifiedPayloadV2, err := publicMakerV2.VerifyToken(publicTokenStringV2)
  if err != nil {
    _ = fmt.Errorf("failed to verify Paseto V2 public token: %w", err)
  }

  // Display verified payload in JSON
  fmt.Println("Verified Paseto V2 public Payload (JSON):")
  fmt.Println(toJSON(publicVerifiedPayloadV2))

  // ** Paseto V3 Local **
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


```
### Output
```sh
Created Paseto V2 local Token (JSON):
{
  "expiration": "2024-12-07T23:49:30.9409531-05:00",
  "payload": {
    "id": "7eb48f33-24f4-474c-a5c5-7cb63883a331",
    "username": "alice",
    "issued_at": "2024-12-06T23:49:30.9409531-05:00",
    "expired_at": "2024-12-07T23:49:30.9409531-05:00"
  },
  "token": "v2.local.T2CMlv2Xv33gh3Huzja01qgiVakqI2YktI5cy1Jz3RWQ2nE4EtvemjI-tWsTwTIBVlfVhAbeTT1gYzzbZbefu0JLUyiNLPH_4B3aRx_hbcXiRqntfgDbzfp4WMCXnMUxgqtkhwDHIpeRGFIggB8CO0pM7jZ6xafU5NT4o3ShjqAYvwKnUcqIpWiX11BdRUX_XEC5g07pMIY1dGgV7vVRk2d6Azpl_1_0hF-N7-jU59MC0ss5twuaN9w6iZmJS805fI-TXZ-lCGyE0mK1nX4"
}
Verified Paseto V2 local Payload (JSON):
{
  "id": "7eb48f33-24f4-474c-a5c5-7cb63883a331",
  "username": "alice",
  "issued_at": "2024-12-06T23:49:30-05:00",
  "expired_at": "2024-12-07T23:49:30-05:00"
}
Created Paseto V2 public Token (JSON):
{
  "expiration": "2024-12-07T23:49:30.9425123-05:00",
  "payload": {
    "id": "b27cfb6e-c97d-4e61-a9e2-7c2021be6752",
    "username": "charlie",
    "issued_at": "2024-12-06T23:49:30.9425123-05:00",
    "expired_at": "2024-12-07T23:49:30.9425123-05:00"
  },
  "token": "v2.public.eyJleHAiOiIyMDI0LTEyLTA3VDIzOjQ5OjMwLTA1OjAwIiwiaWF0IjoiMjAyNC0xMi0wNlQyMzo0OTozMC0wNTowMCIsImlkIjoiYjI3Y2ZiNmUtYzk3ZC00ZTYxLWE5ZTItN2MyMDIxYmU2NzUyIiwibmJmIjoiMjAyNC0xMi0wNlQyMzo0OTozMC0wNTowMCIsInVzZXJuYW1lIjoiY2hhcmxpZSJ95MefI5mWU80uPvxJislx7YJnrsnmAd8uT7wibBJJe4sXiZBsvT5eWpTbfne--BHByis_D7iFhpiF5a0Cab0OBg"
}
Verified Paseto V2 public Payload (JSON):
{
  "id": "b27cfb6e-c97d-4e61-a9e2-7c2021be6752",
  "username": "charlie",
  "issued_at": "2024-12-06T23:49:30-05:00",
  "expired_at": "2024-12-07T23:49:30-05:00"
}
Created Paseto V3 local Token (JSON):
{
  "expiration": "2024-12-07T23:49:30.9436696-05:00",
  "payload": {
    "id": "223496f0-4ddd-4fa3-a6bd-7b7866db28d1",
    "username": "bob",
    "issued_at": "2024-12-06T23:49:30.9436696-05:00",
    "expired_at": "2024-12-07T23:49:30.9436696-05:00"
  },
  "token": "v3.local.7xJYvv0IAu85KYmR3voxEaDbtkn-L7c1HYk2zcIsU9A9RpeHPZ_NPOQ1ARS89EFvPCYuTfIU3vnvuS1ONxhYZimEAqdPwDFZRBrykCXRB-yYcMnApZkqRoGRDosqviCsc_52eiD3jsSr8Q9UO4OBgUpgvP1wNigAcCIPt5QfXC0CK-I3JauL19EZfWAc-0hQPVkKX-L-r8Tg9BWC2xqaw7CqbwuiMX3XRMXDnwYWu2axvTlNSjBzcfFUtMDy3Cdn7_IbTIakZkxHkgTWDW-QWsPjxZzsx2u6XEdApLqEb-VW0Z0Bun2-BhJ_UjQh_ubqjDO3dw"
}
Verified Paseto V3 local Payload (JSON):
{
  "id": "223496f0-4ddd-4fa3-a6bd-7b7866db28d1",
  "username": "bob",
  "issued_at": "2024-12-06T23:49:30-05:00",
  "expired_at": "2024-12-07T23:49:30-05:00"
}
Created Paseto V3 public Token (JSON):
{
  "expiration": "2024-12-07T23:49:30.9448706-05:00",
  "payload": {
    "id": "f3189d84-2931-49df-ae2a-c0b4880207ce",
    "username": "dave",
    "issued_at": "2024-12-06T23:49:30.9448706-05:00",
    "expired_at": "2024-12-07T23:49:30.9448706-05:00"
  },
  "token": "v3.public.eyJleHAiOiIyMDI0LTEyLTA3VDIzOjQ5OjMwLTA1OjAwIiwiaWF0IjoiMjAyNC0xMi0wNlQyMzo0OTozMC0wNTowMCIsImlkIjoiZjMxODlkODQtMjkzMS00OWRmLWFlMmEtYzBiNDg4MDIwN2NlIiwibmJmIjoiMjAyNC0xMi0wNlQyMzo0OTozMC0wNTowMCIsInVzZXJuYW1lIjoiZGF2ZSJ9Z6_vP-lkPTFG5qq3KCKGwUTuh0ScWq4rwIiRhkv_DcEV8vSO7KTSJ_beGt85EJkOJE2J0OrPiXcIae2ycRzEckrVAnhZcLLgGQF9HH8uLUmz8Hgsau3bOiWbxJzas2il"
}
Verified Paseto V3 public Payload (JSON):
{
  "id": "f3189d84-2931-49df-ae2a-c0b4880207ce",
  "username": "dave",
  "issued_at": "2024-12-06T23:49:30-05:00",
  "expired_at": "2024-12-07T23:49:30-05:00"
}
```
## Testing
To run the tests, execute the following command:
```sh
make test
```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
![Coverage](./coverage.svg)
