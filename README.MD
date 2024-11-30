
# Authentication token module for Golang

A Golang module for generating various types of authentication tokens seamlessly using [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) or [PASETO](https://paseto.io/).

## Features
- **JSON WEB TOKEN**: Generate JWT tokens.
- **PASETO SYMMETRIC**: Generate Symmetric PASETO tokens.
- **PASETO ASYMMETRICAL**: Generate ASymmetrical PASETO tokens.

---

## Installation
Get started by installing the package:

```sh
go get github.com/fsobh/token
```

---

## Usage (access + refresh token example)

#### Three types of tokens are supported:

1. **JWT**
```go
package main

import (
"encoding/json"
"fmt"
"github.com/fsobh/token"
"time"
)

type User struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    //...Other fields depending on the application
}

type Response struct {
    User                  User      `json:"user"`
    AccessToken           string    `json:"access_token"`
    RefreshToken          string    `json:"refresh_token"`
    AccessTokenExpiredAt  time.Time `json:"access_token_expired_at"`
    RefreshTokenExpiredAt time.Time `json:"refresh_token_expired_at"`
}

func main() {
        /*
        Never paste your credentials directly in the code for safety reasons
        Recommended : Store these in environment variables using [viper](https://github.com/spf13/viper)
        */
        accessTokenDuration, _ := time.ParseDuration("1h")
        refreshTokenDuration, _ := time.ParseDuration("24h")
        jwtSecret := "a37b1c92fe2d48f652ab7698c60bc7364d45ef12093a02158c90868741f22c4d"

	user := &User{
		Username: "foo",
		Email:    "bar@example.com",
	}

	jwtMaker, err := token.NewJWTMaker(jwtSecret) // Create a new JWT maker

	if err != nil {
		panic(fmt.Errorf("cannot create token maker: %w", err))
	}

	// Create a new access token
	accessToken, accessPayload, err := jwtMaker.CreateToken(user.Username, accessTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create access token : %w", err))
	}

	// Create a new refresh token
	refreshToken, refreshPayload, err := jwtMaker.CreateToken(user.Username, refreshTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create refresh token : %w", err))
	}

	// example response
	response := &Response{
		User:                  *user,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiredAt:  accessPayload.ExpiredAt,
		RefreshTokenExpiredAt: refreshPayload.ExpiredAt,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "  ")

	if err != nil {
		panic(fmt.Errorf("cannot marshal response to JSON: %w", err))
	}

	// Print the JSON response
	fmt.Println(string(jsonResponse))
}
```
**output**: 
```json
{
  "user": {
    "username": "foo",
    "email": "bar@example.com"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjI4MWE3NTlkLTVkNjQtNDNhZS05YmFhLTgwMTc0YTUyZjRiNiIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDo0MTo1NS42NzM5ODQ1LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTEtMzBUMTU6NDE6NTUuNjczOTg0NS0wNTowMCJ9.hHxuqudYIKlq5IvcGpo6Z-jbTUKiX2HYgMn_8oDEEsk",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRmMzlhODFjLTQ3NGUtNDY0MS1iYTc4LTJjN2E2MDJjNjAwNyIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDo0MTo1NS42NzUwNjQ3LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTItMDFUMTQ6NDE6NTUuNjc1MDY0Ny0wNTowMCJ9.NfdeWq9-Q_vl8ONdV4jpjtAhjN3k3TQWAX7t3Er1oL8",
  "access_token_expired_at": "2024-11-30T15:41:55.6739845-05:00",
  "refresh_token_expired_at": "2024-12-01T14:41:55.6750647-05:00"
}
```
2. **PASETO SYMMETRIC**
```go
package main

import (
	"encoding/json"
	"fmt"
	"github.com/fsobh/token"
	"time"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	//...Other fields depending on the application
}

type Response struct {
	User                  User      `json:"user"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiredAt  time.Time `json:"access_token_expired_at"`
	RefreshTokenExpiredAt time.Time `json:"refresh_token_expired_at"`
}

func main() {
	/*
	 Never paste your credentials directly in the code for safety reasons
	 Recommended : Store these in environment variables using [viper](https://github.com/spf13/viper)
	*/
	accessTokenDuration, _ := time.ParseDuration("1h")
	refreshTokenDuration, _ := time.ParseDuration("24h")
	paestSymSecret := "Pq8rNzV4LpD2XsYwdQfTkMaL9JoCvReT"

	user := &User{
		Username: "foo",
		Email:    "bar@example.com",
	}

	pasetoMaker, err := token.NewPasetoMaker(paestSymSecret) // Create a new Paseto maker

	if err != nil {
		panic(fmt.Errorf("cannot create token maker: %w", err))
	}

	accessToken, payload, err := pasetoMaker.CreateToken(user.Username, accessTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create access token : %w", err))
	}

	refreshToken, payload, err := pasetoMaker.CreateToken(user.Username, refreshTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create refresh token : %w", err))

	}

	// example response
	response := &Response{
		User:                  *user,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiredAt:  payload.ExpiredAt,
		RefreshTokenExpiredAt: payload.ExpiredAt,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "  ")

	if err != nil {
		panic(fmt.Errorf("cannot marshal response to JSON: %w", err))
	}

	fmt.Println(string(jsonResponse))
}
```
**output**:
```json
{
  "user": {
    "username": "foo",
    "email": "bar@example.com"
  },
  "access_token": "v2.local.4r-RKdIVKKA-5PuiIl2Rmonq-KY3FsAJzFnWFXT3wycrqt6m0w8DSCTxC51w3qo4kH53M1uXp-bT0xqELU3nZ3C3t8ZFxsV1lzbXHXPWCyoFRWoq4ibTREcNWjShR9S3AelCDPCjMs6wfP8qPJj6nu2aMw2c1IIP_kKL6wxnf-uHieXWM5BNPzk45iUb-T1NqXD_RjjCjdQ0hpvb1FOlAYyu1-jZpLyG11ygiHWB7m3DYfTRt8yS2lBsGP68vNnLjtGkLbU.bnVsbA",
  "refresh_token": "v2.local.mk_fdz7GuGhXJgH2nd3yfksnc-k8JTXeSMWpMNciS9kfShKyrKXmaGLFiUYGTiMkSMSKMugGqN-rVqPmbp7JG0XNpPxWiiEzMHw3sj9cayUJaBKBD_Rx1XtdcCCSzfEtxp5AVkA9qfHrE6Q44NasDpmeSylevFyI_CTwJRP7NEb4UIE5NevdbLxJcrsub7t8CvaVekxdBaJbTRHg9wFgO_qXYhTD7r9jWoNQcm5ea977is7Y8ZtHZNx5ACYn0XthsFJg8jw.bnVsbA",
  "access_token_expired_at": "2024-12-01T14:40:44.819082-05:00",
  "refresh_token_expired_at": "2024-12-01T14:40:44.819082-05:00"
}

```
3. **PASETO ASYMMETRIC**
```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/fsobh/token"
	"os"
	"time"
)

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	//...Other fields depending on the application
}

type Response struct {
	User                  User      `json:"user"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiredAt  time.Time `json:"access_token_expired_at"`
	RefreshTokenExpiredAt time.Time `json:"refresh_token_expired_at"`
}



func base64StringToBytes(keyString string) []byte {
	key, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		_ = fmt.Errorf("cannot decode Keys: %w", err)
		os.Exit(1)
	}
	return key
}

func main() {
	/*
	 Never paste your credentials directly in the code for safety reasons
	 Recommended : Store these in environment variables using [viper](https://github.com/spf13/viper)
	*/
	accessTokenDuration, _ := time.ParseDuration("1h")
	refreshTokenDuration, _ := time.ParseDuration("24h")
	privateKeyString := "B1oTYX0S4+qGfPQSb3DZ6uEo1KyciMTDKp7WnYFPxLEMP5lK1h9TYcMzWJx7ZmID6QtVeKdPW5eTpF7kUKXM6w=="
	publicKeyString := "Mh9TYcMzWJx7ZmID6QtVeKdPW5eTpF7kUKXM6z=="

	publicKey := base64StringToBytes(publicKeyString)

	privateKey := base64StringToBytes(privateKeyString)

	pasetoAsymMaker, err := token.NewAsymPasetoMaker(privateKey, publicKey) // Create a new Paseto maker

	if err != nil {
		panic(fmt.Errorf("cannot create token maker: %w", err))
	}

	user := &User{
		Username: "foo",
		Email:    "bar@example.com",
	}

	accessToken, payload, err := pasetoAsymMaker.CreateToken(user.Username, accessTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create access token : %w", err))
	}

	refreshToken, payload, err := pasetoAsymMaker.CreateToken(user.Username, refreshTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create refresh token : %w", err))
	}

	// example response
	response := &Response{
		User:                  *user,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiredAt:  payload.ExpiredAt,
		RefreshTokenExpiredAt: payload.ExpiredAt,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "  ")

	if err != nil {
		panic(fmt.Errorf("cannot marshal response to JSON: %w", err))
	}

	fmt.Println(string(jsonResponse))

}
```
**output**:
```json
{
  "user": {
    "username": "foo",
    "email": "bar@example.com"
  },
  "access_token": "v2.public.eyJpZCI6IjM2ZDlkMmE0LTU5NzYtNGI0OC04MDlhLWJiZTBjNDdjNjMxOCIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDozODoxNy4yODQ1ODA2LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTEtMzBUMTU6Mzg6MTcuMjg0NTgwNi0wNTowMCJ9BMiK9rMEpRpRQkVrMU6Iykyh5mHZKsP6grXmm_1wFQfvNcaeFQ_9O-b8i3i7iW1GAv7p937iEhrGnkkiRgZlAw.bnVsbA",
  "refresh_token": "v2.public.eyJpZCI6IjgxNDQzNzJlLTIyYjgtNDY5Ny04ODYwLTlhZWZlN2RjMjJhMyIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDozODoxNy4yODY2NzQ3LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTItMDFUMTQ6Mzg6MTcuMjg2Njc0Ny0wNTowMCJ9Io7wN7nq08gNOrSDS2HiekqvaMWOqH5lua0beCa0TZsvfju9kxzviMn7kcrzuVZU4ykgT_GxmIpPrO5WjWvSBg.bnVsbA",
  "access_token_expired_at": "2024-12-01T14:38:17.2866747-05:00",
  "refresh_token_expired_at": "2024-12-01T14:38:17.2866747-05:00"
}

```


## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
