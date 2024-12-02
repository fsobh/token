package token

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ed25519"
	"time"
)

type AsymJWTMaker struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewAsymJWTMaker(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (Maker, error) {
	return &AsymJWTMaker{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (maker *AsymJWTMaker) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", payload, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, payload)
	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return "", payload, err
	}

	return signedToken, payload, nil
}

func (maker *AsymJWTMaker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrInvalidMethod
		}
		return maker.publicKey, nil
	}

	parsedToken, err := jwt.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		var verr *jwt.ValidationError
		if errors.As(err, &verr) {
			if errors.Is(verr.Inner, ErrExpiredToken) {
				return nil, ErrExpiredToken
			}
		}
		return nil, ErrInvalidToken
	}

	payload, ok := parsedToken.Claims.(*Payload)
	if !ok {
		return nil, ErrInvalidToken
	}

	return payload, nil
}
