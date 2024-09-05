package repository

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)


type ConfigToConnect struct {
	Host     string
	Port     string
	Username string
	Password string
	DBname   string
	SSLmode  string
}

func ConnectToDB(config ConfigToConnect) (*sqlx.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s username=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.DBname, config.SSLmode)
	return sqlx.Connect("postgres", dsn)
}
