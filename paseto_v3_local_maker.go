package token

import (
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"time"

	"aidanwoods.dev/go-paseto"
)

// PasetoV3Local handles PASETO V3 Local tokens.
type PasetoV3Local struct {
	symmetricKey paseto.V3SymmetricKey
}

// NewPasetoV3Local initializes a new PASETO V3 Local instance with the given symmetric key (in hex format).
func NewPasetoV3Local(symmetricKeyHex string) (*PasetoV3Local, error) {
	// Decode the hexadecimal symmetric key
	keyBytes, err := hex.DecodeString(symmetricKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid symmetric key hex")
	}

	// Ensure the key is exactly 32 bytes, as required by the PASETO V3 specification
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("symmetric key must be 32 bytes long")
	}

	// Use the key bytes to initialize the symmetric key
	symmetricKey, err := paseto.V3SymmetricKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("could not initialize symmetric key: %w", err)
	}

	return &PasetoV3Local{
		symmetricKey: symmetricKey,
	}, nil
}

// CreateToken creates a new PASETO V3 Local token with the given username and duration.
func (maker *PasetoV3Local) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", nil, err
	}

	// Create a new PASETO token
	token := paseto.NewToken()
	token.SetIssuedAt(payload.IssuedAt)
	token.SetNotBefore(payload.IssuedAt)
	token.SetExpiration(payload.ExpiredAt)
	token.SetString("username", payload.Username)
	token.SetString("id", payload.ID.String())

	// Encrypt the token using the symmetric key
	encryptedToken := token.V3Encrypt(maker.symmetricKey, nil)

	return encryptedToken, payload, nil
}

// VerifyToken verifies a given PASETO V3 Local token and returns the payload if valid.
func (maker *PasetoV3Local) VerifyToken(token string) (*Payload, error) {
	// Parse the encrypted token
	parsedToken, err := paseto.NewParser().ParseV3Local(maker.symmetricKey, token, nil)
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
