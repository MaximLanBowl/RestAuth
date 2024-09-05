package models

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	jwt.StandardClaims
	UserID string `json:"user_id"`
}

type Token struct {
	AccessToken  string
	RefreshToken string
	IpAddress    string
}
