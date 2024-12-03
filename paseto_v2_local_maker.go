package token

import (
	"fmt"
	"github.com/o1egl/paseto"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

type PasetoV2Local struct {
	paseto      *paseto.V2
	symmetricKy []byte
}

func NewPasetoV2Local(symmetricKey string) (Maker, error) {

	//Make sure the key is of same length as a paseto symmetric key
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size : must be %d characters", chacha20poly1305.KeySize)
	}

	maker := &PasetoV2Local{
		paseto:      paseto.NewV2(),
		symmetricKy: []byte(symmetricKey),
	}

	return maker, nil
}

func (maker *PasetoV2Local) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", payload, err
	}

	token, err := maker.paseto.Encrypt(maker.symmetricKy, payload, nil)

	return token, payload, err
}

func (maker *PasetoV2Local) VerifyToken(token string) (*Payload, error) {

	//decrypt payload
	payload := &Payload{}
	err := maker.paseto.Decrypt(token, maker.symmetricKy, payload, nil)

	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()

	if err != nil {
		return nil, err
	}

	return payload, nil
}
