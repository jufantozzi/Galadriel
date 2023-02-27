package util

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"time"
)

func GenerateAccessToken() (string, error) {
	token, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID token: %v", err)
	}
	return token.String(), nil
}

func GenerateJWT(claims jwt.Claims, key *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func GenerateJWTClaims(td string, expiry time.Duration) jwt.MapClaims {
	return jwt.MapClaims{
		"trust-domain": td,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(expiry).Unix(),
	}
}
