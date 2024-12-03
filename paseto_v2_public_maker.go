package token

import (
	"github.com/o1egl/paseto"
	"golang.org/x/crypto/ed25519"
	"time"
)

type PasetoV2Public struct {
	paseto     *paseto.V2
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewPasetoV2Public(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (Maker, error) {
	maker := &PasetoV2Public{
		paseto:     paseto.NewV2(),
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return maker, nil
}

func (maker *PasetoV2Public) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)

	if err != nil {
		return "", payload, err
	}

	token, err := maker.paseto.Sign(maker.privateKey, payload, nil)

	return token, payload, err
}

func (maker *PasetoV2Public) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}
	err := maker.paseto.Verify(token, maker.publicKey, payload, nil)

	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, ErrExpiredToken
	}

	return payload, nil
}
