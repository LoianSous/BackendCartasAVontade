package db

import (
    "database/sql"
    "fmt"
    "os"

    _ "github.com/lib/pq"
)

var DB *sql.DB

func Connect() (*sql.DB, error) {
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        return nil, fmt.Errorf("DATABASE_URL não encontrada no ambiente")
    }

    database, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("erro ao abrir conexão: %v", err)
    }

    if err := database.Ping(); err != nil {
        return nil, fmt.Errorf("erro ao testar conexão: %v", err)
    }

    DB = database
    fmt.Println("Banco conectado com sucesso ao Supabase!")
    return DB, nil
}
