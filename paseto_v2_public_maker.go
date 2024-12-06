package token

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type PasetoV2Public struct {
	privateKey paseto.V2AsymmetricSecretKey
	publicKey  paseto.V2AsymmetricPublicKey
}

func NewPasetoV2Public(privateKeyHex, publicKeyHex string) (*PasetoV2Public, error) {
	privateKey, err := paseto.NewV2AsymmetricSecretKeyFromHex(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("could not initialize private asymmetric key: %w", err)
	}

	publicKey, err := paseto.NewV2AsymmetricPublicKeyFromHex(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("could not initialize public asymmetric key: %w", err)
	}

	maker := &PasetoV2Public{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return maker, nil
}

func (maker *PasetoV2Public) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", payload, fmt.Errorf("could not initialize payload: %w", err)
	}

	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(duration))
	token.SetString("username", payload.Username)
	token.SetString("id", payload.ID.String())
	signedToken := token.V2Sign(maker.privateKey)
	return signedToken, payload, nil
}

func (maker *PasetoV2Public) VerifyToken(token string) (*Payload, error) {
	parsedToken, err := paseto.NewParser().ParseV2Public(maker.publicKey, token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	idString, err := parsedToken.GetString("id")
	if err != nil {
		return nil, ErrInvalidToken
	}

	id, err := uuid.Parse(idString)
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
		ID:        id,
		Username:  username,
		IssuedAt:  issuedAt,
		ExpiredAt: expiredAt,
	}

	return payload, nil
}
