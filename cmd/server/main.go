// @title API de Autenticação
// @version 1.0
// @description API feita em Go com Gin para registrar e logar usuários
// @host localhost:8080
// @BasePath /
package main

import (
    _ "backend/cmd/server/docs"
    "backend/internal/db"
    "backend/internal/handlers"
    "log"
    "os"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    ginSwagger "github.com/swaggo/gin-swagger"
    swaggerFiles "github.com/swaggo/files"

    "github.com/joho/godotenv"
)

func main() {

    // 1. Carrega .env
    if err := godotenv.Load(); err != nil {
        log.Println("Aviso: .env não encontrado, usando variáveis do sistema.")
    }

    // 2. Verifica variável DATABASE_URL
    if os.Getenv("DATABASE_URL") == "" {
        log.Fatal("ERRO: DATABASE_URL NÃO ESTÁ DEFINIDO no ambiente.")
    }

    // 3. Conecta ao banco
    database, err := db.Connect()
    if err != nil {
        log.Fatal("Erro ao conectar no banco:", err)
    }

    // 4. Cria handlers
    h := handlers.NewHandler(database)

    // 5. Configura servidor
    r := gin.Default()

    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"*"},
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
    }))

    // 6. Usa as rotas corretas — COM MIDDLEWARE
    h.SetupRoutes(r)

    // 7. Swagger
    r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

    // 8. Inicia o servidor
    r.Run("0.0.0.0:8080")
}
