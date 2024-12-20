package token

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type PasetoV3Public struct {
	privateKey paseto.V3AsymmetricSecretKey
	publicKey  paseto.V3AsymmetricPublicKey
}

func NewPasetoV3Public(privateKeyHex, publicKeyHex string) (*PasetoV3Public, error) {
	privateKey, err := paseto.NewV3AsymmetricSecretKeyFromHex(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("could not initialize private asymmetric key: %w", err)
	}

	publicKey, err := paseto.NewV3AsymmetricPublicKeyFromHex(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("could not initialize public asymmetric key: %w", err)
	}

	maker := &PasetoV3Public{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	return maker, nil
}

func (maker *PasetoV3Public) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
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

	signedToken := token.V3Sign(maker.privateKey, nil)
	return signedToken, payload, nil
}

func (maker *PasetoV3Public) VerifyToken(token string) (*Payload, error) {
	parsedToken, err := paseto.NewParser().ParseV3Public(maker.publicKey, token, nil)
	if err != nil {
		return nil, fmt.Errorf("could not parse payload: %s", err)
	}

	idString, err := parsedToken.GetString("id")
	if err != nil {
		return nil, ErrInvalidToken
	}

	id, err := uuid.Parse(idString)
	if err != nil {
		return nil, fmt.Errorf("could not parse guid to string: %s", err)
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
