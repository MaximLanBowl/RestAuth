package main

import (
	"net/http"
	"os"

	"github.com/MaximLanBowl/RestAuth.git/internal/handlers"

	"github.com/MaximLanBowl/RestAuth.git/internal/repository"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
    if err := initConfig(); err != nil {
        logrus.Fatalf("Failed to init config %s", err)
        return
    }

    if err := godotenv.Load(); err != nil {
        logrus.Fatal("Failed to load env file", err.Error())
    }

    db, err := repository.ConnectToDB(repository.ConfigToConnect{
        Host:     viper.GetString("db.Host"),
        Port:     viper.GetString("db.Port"),
        Username: viper.GetString("db.Username"),
        Password: os.Getenv("DB_PASSWORD"),
        DBname:   viper.GetString("db.DBname"),
        SSLmode:  viper.GetString("db.SSLmode"),
    })

	if err != nil {
        logrus.Fatalf("Failed to connect to DataBase %s", err.Error())
    }

	defer db.Close()

    http.HandleFunc("/access-token", handlers.AccessTokenHandler)
    http.HandleFunc("/refresh-token", handlers.RefreshTokenHandler)
    logrus.Infof("Server started on port 8080")
    http.ListenAndServe(":8080", nil)
}

func initConfig() error {
    viper.AddConfigPath("configs")
    viper.SetConfigName("config")
    return viper.ReadInConfig()
}


