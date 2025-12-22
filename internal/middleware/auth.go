package middleware

import (
    "log"
    "strings"
    "net/http"

    "github.com/gin-gonic/gin"
    "backend/internal/services"
)

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {

        log.Println("🔒 [MIDDLEWARE] AuthMiddleware chamado")

        authHeader := c.GetHeader("Authorization")
        log.Println("📩 Header Authorization recebido:", authHeader)

        if authHeader == "" {
            log.Println("❌ Token não enviado")
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Token não enviado"})
            c.Abort()
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            log.Println("❌ Formato do token inválido")
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
            c.Abort()
            return
        }

        tokenStr := parts[1]
        log.Println("🔍 Token bruto extraído:", tokenStr)

        // Agora ValidateToken retorna (userID string, err error)
        userID, err := services.ValidateToken(tokenStr)
        if err != nil {
            log.Println("❌ Erro ao validar token:", err)
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
            c.Abort()
            return
        }

        log.Println("🔑 userId extraído do token:", userID)

        // Injeta no contexto — AGORA É STRING ✔️
        c.Set("userId", userID)

        c.Next()
    }
}
