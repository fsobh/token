package token

import (
	"aidanwoods.dev/go-paseto"
	"encoding/hex"
	"fmt"
	"time"
)

type PasetoV2Local struct {
	symmetricKey paseto.V2SymmetricKey
}

func NewPasetoV2Local(symmetricKeyHex string) (*PasetoV2Local, error) {
	// Decode the hexadecimal symmetric key
	keyBytes, err := hex.DecodeString(symmetricKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid symmetric key hex")
	}

	// Ensure the key is exactly 32 bytes, as required by the PASETO V2 specification
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("symmetric key must be 32 bytes long")
	}

	// Use the key bytes to initialize the symmetric key
	symmetricKey, err := paseto.V2SymmetricKeyFromBytes(keyBytes)

	if err != nil {
		return nil, fmt.Errorf("could not initialize symmetric keys from bytes : %d", err)
	}

	return &PasetoV2Local{
		symmetricKey: symmetricKey,
	}, nil
}

func (maker *PasetoV2Local) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", payload, err
	}

	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(duration))
	token.SetString("username", payload.Username)

	encryptedToken := token.V2Encrypt(maker.symmetricKey)
	return encryptedToken, payload, nil
}

func (maker *PasetoV2Local) VerifyToken(token string) (*Payload, error) {
	parsedToken, err := paseto.NewParser().ParseV2Local(maker.symmetricKey, token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	username, err := parsedToken.GetString("username")
	if err != nil {
		return nil, ErrInvalidToken
	}

	issuedAt, err := parsedToken.GetIssuedAt()
	if err != nil {
		return nil, ErrInvalidToken
	}

	expiredAt, err := parsedToken.GetExpiration()
	if err != nil {
		return nil, ErrInvalidToken
	}

	payload := &Payload{
		Username:  username,
		IssuedAt:  issuedAt,
		ExpiredAt: expiredAt,
	}

	err = payload.Valid()
	if err != nil {
		return nil, ErrExpiredToken
	}

	return payload, nil
}
