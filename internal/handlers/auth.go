package handlers

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

	"github.com/MaximLanBowl/RestAuth.git/internal/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var db *sqlx.DB

const (
	tokenTimer = 24 * time.Hour
	salt = "qwertyuiopasdfghjklzxcvbnmQWJEQWNIORQWNDQWMASACIOSAS1234567890"
)

func AccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}
	accessClaims := &models.Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenTimer).Unix(),
		},
		UserID: userID,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(salt))
	if err != nil {
		logrus.Error(err)
	}
	refreshToken := generateRandomString(32)
	if err != nil {
		logrus.Infof("Failed to generate random string")
		logrus.Error(err)
	}

	tokenResponse := models.Token{
		AccessToken: signedAccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(refreshToken)),
	}
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)
}
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id") 

    if userID == "" {
        http.Error(w, "user_id is required", http.StatusBadRequest)
        return
    }

    var req struct {
        RefreshToken string `json:"refresh_token"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "could not decode request", http.StatusBadRequest)
        return
    }

    refreshToken, err := base64.StdEncoding.DecodeString(req.RefreshToken) // Декодируем из base64
    if err != nil {
        http.Error(w, "invalid refresh token", http.StatusBadRequest)
        return
    }

    if !isRefreshTokenValid(string(refreshToken)) {
        http.Error(w, "invalid or expired refresh token", http.StatusUnauthorized)
        return
    }

    accessClaims := &models.Claims{
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(tokenTimer).Unix(),
        },
    }

    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
    signedAccessToken, err := accessToken.SignedString([]byte("your_secret_key"))
    if err != nil {
        logrus.Error(err)
        http.Error(w, "could not generate access token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(struct {
        AccessToken string `json:"access_token"`
    }{
        AccessToken: signedAccessToken,
    })
}

func generateRandomString(length int) string {
	res := make([]byte, length)
	for v := range res {
		res[v] = salt[rand.Intn(len(salt))]
	}
	return string(res)
}


func isRefreshTokenValid(refreshToken string) bool {
    rows, err := db.Query("SELECT token FROM refresh_tokens WHERE user_id = $1", refreshToken)
    if err != nil {
        return false
    }
    defer rows.Close()

    var hashedToken string
    if rows.Next() {
        if err := rows.Scan(&hashedToken); err != nil {
            return false
        }

        if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken)); err != nil {
            return false
        }
        return true
    }
    return false
}
