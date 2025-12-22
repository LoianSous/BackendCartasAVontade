package services

import (
    "errors"
    "os"
    "time"
    "github.com/golang-jwt/jwt/v5"
)

var jwtSecret []byte

func init() {
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        secret = "dev-secret-change-me"
    }
    jwtSecret = []byte(secret)
}

// Claims customizados — AGORA userID é string
type CustomClaims struct {
    UserID string `json:"user_id"`
    jwt.RegisteredClaims
}

// Agora GenerateToken recebe string
func GenerateToken(userID string) (string, error) {
    expHours := 720 // 30 dias

    claims := CustomClaims{
        UserID: userID,
        RegisteredClaims: jwt.RegisteredClaims{
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(expHours))),
            Issuer:    "your-app-name",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtSecret)
}

// ValidateToken retorna string agora
func ValidateToken(tokenString string) (string, error) {
    if tokenString == "" {
        return "", errors.New("token vazio")
    }

    token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    if err != nil {
        return "", err
    }

    if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
        return claims.UserID, nil
    }

    return "", errors.New("token inválido")
}
