
# Authentication token module for Golang

A Golang module for generating & verifying various types of authentication tokens seamlessly using [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) or [PASETO](https://paseto.io/).

## Features
- **JSON WEB TOKEN SYMMETRIC**: Generate Symmetric JWT tokens.
- **JSON WEB TOKEN ASYMMETRIC**: Generate Asymmetric JWT tokens.
- **PASETO SYMMETRIC**: Generate Symmetric PASETO tokens.
- **PASETO ASYMMETRICAL**: Generate Asymmetrical PASETO tokens.

---

## Installation
Get started by installing the package:

```sh 
go get github.com/fsobh/token
```

---

## Usage (access + refresh token example)

#### Four types of tokens are supported:

1. **JWT SYMMETRIC**
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
	
	fmt.Println(string(jsonResponse))

	//example to verify :

	payload, err := jwtMaker.VerifyToken(accessToken)

	jsonResponse, err = json.MarshalIndent(payload, "", "  ")

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
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjI4MWE3NTlkLTVkNjQtNDNhZS05YmFhLTgwMTc0YTUyZjRiNiIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDo0MTo1NS42NzM5ODQ1LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTEtMzBUMTU6NDE6NTUuNjczOTg0NS0wNTowMCJ9.hHxuqudYIKlq5IvcGpo6Z-jbTUKiX2HYgMn_8oDEEsk",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImRmMzlhODFjLTQ3NGUtNDY0MS1iYTc4LTJjN2E2MDJjNjAwNyIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMS0zMFQxNDo0MTo1NS42NzUwNjQ3LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTItMDFUMTQ6NDE6NTUuNjc1MDY0Ny0wNTowMCJ9.NfdeWq9-Q_vl8ONdV4jpjtAhjN3k3TQWAX7t3Er1oL8",
  "access_token_expired_at": "2024-11-30T15:41:55.6739845-05:00",
  "refresh_token_expired_at": "2024-12-01T14:41:55.6750647-05:00"
}

//verify output
{
  "id": "c3c2b27e-0f96-4160-9b1d-4613dc87ec73",
  "username": "foo",
  "issued_at": "2024-12-01T00:33:32.9286814-05:00",
  "expired_at": "2024-12-01T01:33:32.9286814-05:00"
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

	accessToken, accessPayload, err := pasetoMaker.CreateToken(user.Username, accessTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create access token : %w", err))
	}

	refreshToken, refreshPayload, err := pasetoMaker.CreateToken(user.Username, refreshTokenDuration)

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

	fmt.Println(string(jsonResponse))

	//verify : 
	payload, err := pasetoMaker.VerifyToken(accessToken)

	jsonResponse, err = json.MarshalIndent(payload, "", "  ")

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
  "access_token": "v2.local.7iafWVlEHElGt2m_hr09wY0cP6S4A3f-6NyT34DZlXT6SSisDXvglXHqap0YlcRX0P-o-7bu5JDvxjy6xwD3satHAYtqevg5LptJsjnvP6dHshtBbpuSIYRk6eHhMZV9AXbXS2O1iN6aeD3GvmHmevWsEsdTeaD5p9vs0R5V9pm9yi-hOy76tjMN8giIZNEMyp6yeGnR51HjTh6X1a0iJeKSvvAB8mLppEQQBlTDoxRuM44gxIA9msq8oTtl-8UTBMO8RMH9KQ.bnVsbA",
  "refresh_token": "v2.local.5UXHQUvZbuC9uZEMgYecmbfFS0ddct4RosKIV1QUpHYiDb-aMHuW2cAYGl2MfoIfB2FnEy88ktuKyJwlaZXM-3RJeUN7HfnBemJiCekhKXKhil5uC3-wUP20-cFId95xfMNvctjHXyK7KEWWHcFiABAKZU0UofbSU78JOcSMFeli04DVJp4ZLQlqII5-dAsgDhmWKK_wPAK9bx7HWhk0jTQ3ruopi_xjcJqTxTjukSPWCCSkJLRhciPe4HLf_ZJVTZzo_XSXJw.bnVsbA",
  "access_token_expired_at": "2024-12-02T14:36:20.9491139-05:00",
  "refresh_token_expired_at": "2024-12-03T13:36:20.9496305-05:00"
}
// verify output :
{
  "id": "3394f870-3eb4-49d5-8c98-afc498e18f6d",
  "username": "foo",
  "issued_at": "2024-12-02T13:36:20.9491139-05:00",
  "expired_at": "2024-12-02T14:36:20.9491139-05:00"
}



```
3. **PASETO ASYMMETRIC (Ed25519 public/private key pair)**
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
	privateKeyString := "zcejpWP9EMOcfJfKReRztKqMcEjJGuKO9ONX3ITN+CFZ50OhHy8R9yTirM16ipNJSQaxASttFhJYBNaJWP/rzw=="
	publicKeyString := "WedDoR8vEfck4qzNeoqTSUkGsQErbRYSWATWiVj/688="

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

	accessToken, accessPayload, err := pasetoAsymMaker.CreateToken(user.Username, accessTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create access token : %w", err))
	}

	refreshToken, refreshPayload, err := pasetoAsymMaker.CreateToken(user.Username, refreshTokenDuration)

	if err != nil {
		panic(fmt.Errorf("cannot create refresh token : %w", err))
	}

	
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

	fmt.Println(string(jsonResponse))

	payload, err := pasetoAsymMaker.VerifyToken(accessToken)

	jsonResponse, err = json.MarshalIndent(payload, "", "  ")

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
  "access_token": "v2.public.eyJpZCI6IjU5ODZhYjAxLTM3MDAtNDRhYS04NzA1LTZhNDBiNWYxZjYyNyIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMi0wMlQxMzo0MToxNi4zMTIxODI4LTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTItMDJUMTQ6NDE6MTYuMzEyMTgyOC0wNTowMCJ9mDp-4UpeiPNSUJdkboSdgvp2rT3dZhDa8wKsBq2CImtnjVwkekU2JfZMBltCwUHEAAxx-GqNgm5N3SlBdPwkAA.bnVsbA",
  "refresh_token": "v2.public.eyJpZCI6IjZhYWJkNzEyLWEyOTEtNDc0ZS1iYTEyLTNjYjdlMmFmM2RkNyIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMi0wMlQxMzo0MToxNi4zMTMyMTQtMDU6MDAiLCJleHBpcmVkX2F0IjoiMjAyNC0xMi0wM1QxMzo0MToxNi4zMTMyMTQtMDU6MDAifWtsySYrze2oDHq954KesVgifMT_sFcyf686jnqm9EUbOUNW8S-tBZxtZqLcoCEuDmY8Pu6OqVX0yVaHp6cj7Qs.bnVsbA",
  "access_token_expired_at": "2024-12-02T14:41:16.3121828-05:00",
  "refresh_token_expired_at": "2024-12-03T13:41:16.313214-05:00"
}

//verify output:
{
  "id": "5986ab01-3700-44aa-8705-6a40b5f1f627",
  "username": "foo",
  "issued_at": "2024-12-02T13:41:16.3121828-05:00",
  "expired_at": "2024-12-02T14:41:16.3121828-05:00"
}


```
4. **JWT ASYMMETRIC (Ed25519 public/private key pair)**
```go
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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
	privateKeyString := "kcqWCAG3yLjE7lvuz6SzDlR9Ml5yj9mU1vX+azJD6c4XwTN8vzSL3gN+hiLlDdcfTdMDbck6F2M279E9aYZvqQ=="
	publicKeyString := "F8EzfL80i94DfoYi5Q3XH03TA23JOhdjNu/RPWmGb6k="

	publicKey := base64StringToBytes(publicKeyString)
	privateKey := base64StringToBytes(privateKeyString)

	jwtAsymMaker, err := token.NewAsymJWTMaker(privateKey, publicKey) // Create a new JWT maker
	if err != nil {
		panic(fmt.Errorf("cannot create token maker: %w", err))
	}

	user := &User{
		Username: "foo",
		Email:    "bar@example.com",
	}

	accessToken, accessPayload, err := jwtAsymMaker.CreateToken(user.Username, accessTokenDuration)
	if err != nil {
		panic(fmt.Errorf("cannot create access token: %w", err))
	}

	refreshToken, refreshPayload, err := jwtAsymMaker.CreateToken(user.Username, refreshTokenDuration)
	if err != nil {
		panic(fmt.Errorf("cannot create refresh token: %w", err))
	}

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

	fmt.Println(string(jsonResponse))

	payload, err := jwtAsymMaker.VerifyToken(accessToken)
	if err != nil {
		panic(fmt.Errorf("cannot verify token: %w", err))
	}

	jsonResponse, err = json.MarshalIndent(payload, "", "  ")
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
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpZCI6IjliOTJiNWIyLWIwMWMtNDliZC05ZTExLTkwMTRjMjM4OTcyNCIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMi0wMlQxMjo1NzoxNS4wNjQyMDgtMDU6MDAiLCJleHBpcmVkX2F0IjoiMjAyNC0xMi0wMlQxMzo1NzoxNS4wNjQyMDgtMDU6MDAifQ.NZw881tsaA7CBMXOe51y2OQ7dsRximc6dz0-rdQZN-ofqn2OoVCJ0rHqgfLAhOIxSiPZRgNnfvYG38VLV4fYAw",
  "refresh_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpZCI6ImFjY2NhMzI2LTFjZWUtNDNiYy05N2EyLWUwZjJmNWJhYjc5MCIsInVzZXJuYW1lIjoiZm9vIiwiaXNzdWVkX2F0IjoiMjAyNC0xMi0wMlQxMjo1NzoxNS4wNjUyNTcyLTA1OjAwIiwiZXhwaXJlZF9hdCI6IjIwMjQtMTItMDNUMTI6NTc6MTUuMDY1MjU3Mi0wNTowMCJ9.rN5R43eLq0BNMcGnNXHJTmTZwnbSsKQAyfaJ7Mf0SKctf__GEk2iJxauanc4w73scw0vEAn1kHQmQjvAX7t5AQ",
  "access_token_expired_at": "2024-12-02T13:57:15.064208-05:00",
  "refresh_token_expired_at": "2024-12-03T12:57:15.0652572-05:00"
}

//verify output
{
  "id": "9b92b5b2-b01c-49bd-9e11-9014c2389724",
  "username": "foo",
  "issued_at": "2024-12-02T12:57:15.064208-05:00",
  "expired_at": "2024-12-02T13:57:15.064208-05:00"
}



```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
