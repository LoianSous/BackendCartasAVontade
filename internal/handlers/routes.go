package handlers

import (
    "bytes"
    "os"
    "strings"
    "log"
    "io"
    "fmt"
    "backend/internal/models"
    "backend/internal/services"
    "database/sql"
    "net/http"
    "github.com/gin-gonic/gin"
    "time"
    "backend/internal/middleware"
    "github.com/supabase-community/storage-go"
)

func (h *Handler) SetupRoutes(router *gin.Engine) {

    // ---------------------------
    // ROTAS PÚBLICAS (sem token)
    // ---------------------------
    router.POST("/register", h.Register)
    router.POST("/login", h.Login)
    router.POST("/recover-request", h.RecoverRequest)
    router.POST("/recover-verify", h.RecoverVerify)
    router.POST("/reset-password", h.ResetPassword)

    // A rota GET de compartilhamento PRECISA ser pública!
    router.GET("/letters/share/:token", h.GetLetterByShareToken)


    // ----------------------------------------
    // ROTAS PROTEGIDAS — PRECISAM DE TOKEN JWT
    // ----------------------------------------
    authorized := router.Group("/")
    authorized.Use(middleware.AuthMiddleware())
    {
        authorized.GET("/letters/me", h.GetUserLetters)
        authorized.GET("/me", h.GetProfile)
        authorized.POST("/letters", h.CreateLetter)
        authorized.POST("/letter-photo", h.CreateLetterPhoto)
        authorized.GET("/letters/:id", h.GetLetterById)
        authorized.DELETE("/letters/:id", h.DeleteLetter)
    }
}

type Handler struct {
    DB *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
    return &Handler{DB: db}
}

func NewSupabaseStorage() *storage_go.Client {
    return storage_go.NewClient(
        os.Getenv("SUPABASE_URL"),
        os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
        nil,
    )
}

// RegisterUser godoc
// @Summary Registra um novo usuário
// @Description Cria um usuário com nome, email, username e senha
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "Dados do usuário"
// @Success 201 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /register [post]
func (h *Handler) Register(c *gin.Context) {
    var req models.RegisterRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido"})
        return
    }

    hash, err := services.HashPassword(req.Password)
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao gerar hash"})
        return
    }

    query := `INSERT INTO users (name, username, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())`
    _, err = h.DB.Exec(query, req.Name, req.Username, req.Email, hash)

    if err != nil {
        fmt.Println("ERRO NO INSERT:", err)
        c.JSON(500, gin.H{"error": "Erro ao salvar usuário"})
        return
    }

    c.JSON(201, gin.H{"message": "Usuário registrado"})
}

// LoginUser godoc
// @Summary Faz login do usuário
// @Description Retorna um token JWT válido
// @Tags auth
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Credenciais"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
func (h *Handler) Login(c *gin.Context) {
    var req models.LoginRequest

    log.Println("📥 Recebendo requisição de login...")

    if err := c.ShouldBindJSON(&req); err != nil {
        log.Println("❌ Erro ao fazer bind do JSON:", err)
        c.JSON(400, gin.H{"error": "Preencha os campos por favor"})
        return
    }

    log.Println("➡️  Identifier recebido:", req.Identifier)
    log.Println("➡️  Password recebido:", req.Password) // cuidado! remover depois

    var user models.User

    query := `SELECT id, name, username, email, password_hash FROM users WHERE email=$1 OR username=$1`

    log.Println("🔍 Executando query:", query)
    log.Println("🔍 Parâmetro:", req.Identifier)

    err := h.DB.QueryRow(query, req.Identifier).Scan(
        &user.ID, &user.Name, &user.Username, &user.Email, &user.PasswordHash,
    )

    if err != nil {
        log.Println("⚠️ Usuário não encontrado. Erro do banco:", err)
        c.JSON(400, gin.H{"error": "Usuário não encontrado"})
        return
    }

    log.Println("✅ Usuário encontrado:")
    log.Println("   ID:", user.ID)
    log.Println("   Name:", user.Name)
    log.Println("   Username:", user.Username)
    log.Println("   Email:", user.Email)
    log.Println("   PasswordHash:", user.PasswordHash)

    log.Println("🔑 Validando senha...")

    if !services.CheckPassword(user.PasswordHash, req.Password) {
        log.Println("❌ Senha incorreta para usuário ID:", user.ID)
        c.JSON(401, gin.H{"error": "Senha incorreta"})
        return
    }

    log.Println("🔐 Senha correta! Gerando token...")

    token, err := services.GenerateToken(user.ID)
    if err != nil {
        log.Println("❌ Erro ao gerar token:", err)
        c.JSON(500, gin.H{"error": "Erro ao gerar token"})
        return
    }

    log.Println("🎉 Login concluído com sucesso para usuário ID:", user.ID)
    log.Println("📨 Token gerado:", token)

    c.JSON(200, gin.H{
        "token":    token,
        "id":       user.ID,
        "name":     user.Name,
        "username": user.Username,
        "email":    user.Email,
    })
}


func (h *Handler) RecoverRequest(c *gin.Context) {
    var req models.RecoverEmailRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Email inválido"})
        return
    }

    var userId string
    err := h.DB.QueryRow(`SELECT id::text FROM users WHERE email=$1`, req.Email).Scan(&userId)

    if err != nil {
        c.JSON(400, gin.H{"error": "Email não encontrado"})
        return
    }

    code := services.GenerateCode()
    fmt.Println("USER ID:", userId, "ERR:", err)

    _, err = h.DB.Exec(`
        INSERT INTO recovery_codes (user_id, code, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id)
        DO UPDATE SET code=$2, expires_at=$3, used=false, created_at=CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
    `, userId, code, time.Now().UTC().Add(10 * time.Minute))

    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao salvar código"})
        return
    }

    if err := services.SendEmail(req.Email, code); err != nil {
        fmt.Println("ERRO SMTP:", err)
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{"message": "Código enviado"})
}

func (h *Handler) RecoverVerify(c *gin.Context) {
    var req models.RecoverVerifyRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Dados inválidos"})
        return
    }

    var dbCode string
    var expiresAt time.Time
    var used bool

    err := h.DB.QueryRow(`
        SELECT code, expires_at, used
        FROM recovery_codes
        WHERE user_id = (SELECT id FROM users WHERE email=$1)
    `, req.Email).Scan(&dbCode, &expiresAt, &used)

    if err != nil {
        c.JSON(400, gin.H{"error": "Código não encontrado"})
        return
    }

    if used {
        c.JSON(400, gin.H{"error": "Código já utilizado"})
        return
    }

    
    if time.Now().UTC().After(expiresAt.UTC()) {
        c.JSON(400, gin.H{"error": "Código expirado"})
        return
    }


    if req.Code != dbCode {
        c.JSON(400, gin.H{"error": "Código inválido"})
        return
    }

    // Marca como usado
    h.DB.Exec(`
        UPDATE recovery_codes SET used=true WHERE user_id = (SELECT id FROM users WHERE email=$1)
    `, req.Email)

    c.JSON(200, gin.H{"message": "Código validado"})
}


func (h *Handler) ResetPassword(c *gin.Context) {
    var req models.ResetPasswordRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "JSON inválido"})
        return
    }

    var userId string
    err := h.DB.QueryRow(`SELECT id FROM users WHERE email=$1`, req.Email).Scan(&userId)

    if err != nil {
        c.JSON(400, gin.H{"error": "Email não encontrado"})
        return
    }

    hashed, err := services.HashPassword(req.NewPassword)
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao gerar hash"})
        return
    }

    _, err = h.DB.Exec(`
        UPDATE users SET password_hash=$1 WHERE id=$2
    `, hashed, userId)

    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao atualizar senha"})
        return
    }

    // Limpa códigos usados/velhos
    _, _ = h.DB.Exec(`DELETE FROM recovery_codes WHERE user_id=$1`, userId)

    c.JSON(200, gin.H{"message": "Senha alterada com sucesso"})
}

func (h *Handler) CreateLetter(c *gin.Context) {
    var req models.CreateLetterRequest

    if err := c.ShouldBindJSON(&req); err != nil {
        fmt.Println("❌ Erro ao fazer bind JSON:", err)
        c.JSON(400, gin.H{"error": "JSON inválido"})
        return
    }

    // LOG dos dados enviados
    fmt.Println("📥 Dados recebidos para criar carta:")
    fmt.Printf("%+v\n", req)

    query := `
        INSERT INTO letters (
    user_id, template_id, beloved_name, birthday, favorite_color, compliment,
    from_name, to_name, special_messages, time_together, favorite_movie,
    favorite_food, zodiac_sign, things_they_like, letter_title, share_url, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16, NOW()
)
RETURNING id
    `

    var letterID int
    err := h.DB.QueryRow(
        query,
        req.UserID,
        req.TemplateID,
        req.BelovedName,
        req.Birthday,
        req.FavoriteColor,
        req.Compliment,
        req.FromName,
        req.ToName,
        req.SpecialMessages,
        req.TimeTogether,
        req.FavoriteMovie,
        req.FavoriteFood,
        req.ZodiacSign,
        req.ThingsTheyLike,
        req.LetterTitle,
        req.ShareURL,
    ).Scan(&letterID)

    if err != nil {
        fmt.Println("❌ ERRO AO EXECUTAR INSERT NA TABELA letters:")
        fmt.Println(err) // <--- AQUI VEM O ERRO REAL DO POSTGRES

        c.JSON(500, gin.H{
            "error":   "Erro ao salvar carta",
            "details": err.Error(),
        })
        return
    }

    fmt.Println("✅ Carta salva com sucesso! ID =", letterID)

    c.JSON(201, gin.H{
        "message": "Carta salva!",
        "id":      letterID,
    })
}


func (h *Handler) CreateLetterPhoto(c *gin.Context) {
    var req models.CreateLetterPhotoRequest

    // Log do JSON recebido
    fmt.Println("📸 Recebendo dados para salvar foto...")
    rawBody, _ := io.ReadAll(c.Request.Body)
    fmt.Println("📨 JSON bruto recebido em /letter-photo:", string(rawBody))
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody))

    if err := c.ShouldBindJSON(&req); err != nil {
        fmt.Println("❌ Erro ao fazer bind do JSON:", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Dados inválidos", "details": err.Error()})
        return
    }

    // MOSTRAR O QUE O FRONT REALMENTE ENVIOU
    fmt.Printf("📥 Dados recebidos:\n LetterID: %d\n PhotoURL: %s\n", req.LetterID, req.PhotoURL)

    query := `
        INSERT INTO letter_photos (letter_id, photo_url, created_at)
        VALUES ($1, $2, NOW())
        RETURNING id
    `

    var id int
    err := h.DB.QueryRow(query, req.LetterID, req.PhotoURL).Scan(&id)

    if err != nil {
        fmt.Println("❌ ERRO AO INSERIR NA TABELA letter_photos:")
        fmt.Println(err) // LOG DO ERRO REAL DO POSTGRES

        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "Erro ao salvar foto",
            "details": err.Error(),
        })
        return
    }

    fmt.Println("✅ Foto salva com sucesso! ID:", id)

    c.JSON(201, gin.H{
        "message": "Foto salva",
        "id":      id,
    })
}

// GetLetterByShareToken - retorna carta pública pelo share_url
func (h *Handler) GetLetterByShareToken(c *gin.Context) {
    token := c.Param("token")

    if token == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Token inválido"})
        return
    }

    // Consulta carta
    queryLetter := `
        SELECT id, user_id, template_id, beloved_name, birthday, favorite_color,
               compliment, from_name, to_name, special_messages, time_together,
               favorite_movie, favorite_food, zodiac_sign, things_they_like,
               letter_title, share_url, created_at
        FROM letters
        WHERE share_url = $1
    `

    var letter models.CreateLetterRequest
    var letterID int

    err := h.DB.QueryRow(queryLetter, token).Scan(
        &letterID,
        &letter.UserID,
        &letter.TemplateID,
        &letter.BelovedName,
        &letter.Birthday,
        &letter.FavoriteColor,
        &letter.Compliment,
        &letter.FromName,
        &letter.ToName,
        &letter.SpecialMessages,
        &letter.TimeTogether,
        &letter.FavoriteMovie,
        &letter.FavoriteFood,
        &letter.ZodiacSign,
        &letter.ThingsTheyLike,
        &letter.LetterTitle,
        &letter.ShareURL,
        new(time.Time),
    )

    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Carta não encontrada"})
        return
    }

    // Busca fotos
    rows, err := h.DB.Query(`
        SELECT photo_url
        FROM letter_photos
        WHERE letter_id = $1
    `, letterID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao buscar fotos"})
        return
    }
    defer rows.Close()

    photos := []string{}
    for rows.Next() {
        var url string
        rows.Scan(&url)
        photos = append(photos, url)
    }

    c.JSON(200, gin.H{
        "id":     letterID,
        "letter": letter,
        "photos": photos,
    })
}

func (h *Handler) GetUserLetters(c *gin.Context) {
    log.Println("📬 [GetUserLetters] Requisição recebida")

    // Recupera userId vindo do middleware JWT
    uid, exists := c.Get("userId")
    log.Printf("🔍 [GetUserLetters] Valor bruto de uid: %v (type=%T)\n", uid, uid)

    if !exists {
        log.Println("❌ [GetUserLetters] userId não existe no contexto. Middleware não setou!")
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuário não autenticado"})
        return
    }

    // Converter para string (pois agora userID é UUID!)
    var userID string

    switch v := uid.(type) {
    case string:
        userID = v
    default:
        log.Printf("❌ [GetUserLetters] Tipo inesperado no contexto. Esperado string, recebido %T\n", uid)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "userId inválido no contexto"})
        return
    }

    log.Printf("✅ [GetUserLetters] userID final: %s\n", userID)

    // Query
    query := `
        SELECT id, letter_title, share_url
        FROM letters
        WHERE user_id = $1
        ORDER BY id DESC
   `

    log.Println("📝 [GetUserLetters] Executando query SQL...")
    log.Printf("➡️  SQL: %s\n", query)
    log.Printf("➡️  Param: %s\n", userID)

    rows, err := h.DB.Query(query, userID)
    if err != nil {
        log.Printf("❌ [GetUserLetters] Erro ao executar query: %v\n", err)
        c.JSON(500, gin.H{"error": "Erro ao buscar cartas", "details": err.Error()})
        return
    }
    defer rows.Close()

    log.Println("📨 [GetUserLetters] Lendo resultados...")

    letters := []map[string]interface{}{}

    for rows.Next() {
        var id int
        var title sql.NullString
        var shareURL sql.NullString

        if err := rows.Scan(&id, &title, &shareURL); err != nil {
            log.Printf("❌ [GetUserLetters] Erro ao fazer Scan: %v\n", err)
            c.JSON(500, gin.H{"error": "Erro ao ler resultado", "details": err.Error()})
            return
        }

        log.Printf("📄 [GetUserLetters] Carta encontrada → id=%d title=%s share=%s\n",
            id, title.String, shareURL.String)

        letters = append(letters, map[string]interface{}{
            "id":           id,
            "letter_title": title.String,
            "share_url":    shareURL.String,
        })
    }

    if len(letters) == 0 {
        log.Println("📭 [GetUserLetters] Nenhuma carta encontrada")
    }

    log.Println("✅ [GetUserLetters] Retornando resposta para o cliente")

    c.JSON(200, letters)
}

func (h *Handler) GetLetterById(c *gin.Context) {
    id := c.Param("id")

    query := `
        SELECT id, user_id, template_id, beloved_name, birthday, favorite_color,
               compliment, from_name, to_name, special_messages, time_together,
               favorite_movie, favorite_food, zodiac_sign, things_they_like,
               letter_title, share_url
        FROM letters
        WHERE id = $1
    `

    var letter models.CreateLetterRequest
    var letterID int
    err := h.DB.QueryRow(query, id).Scan(
        &letterID,
        &letter.UserID,
        &letter.TemplateID,
        &letter.BelovedName,
        &letter.Birthday,
        &letter.FavoriteColor,
        &letter.Compliment,
        &letter.FromName,
        &letter.ToName,
        &letter.SpecialMessages,
        &letter.TimeTogether,
        &letter.FavoriteMovie,
        &letter.FavoriteFood,
        &letter.ZodiacSign,
        &letter.ThingsTheyLike,
        &letter.LetterTitle,
        &letter.ShareURL,
    )

    if err != nil {
        c.JSON(404, gin.H{"error": "Carta não encontrada"})
        return
    }

    // Buscar fotos da carta
    rows, err := h.DB.Query(`SELECT photo_url FROM letter_photos WHERE letter_id=$1`, letterID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao carregar fotos"})
        return
    }
    defer rows.Close()

    photos := []string{}
    for rows.Next() {
        var url string
        rows.Scan(&url)
        photos = append(photos, url)
    }

    c.JSON(200, gin.H{
        "id":     letterID,
        "letter": letter,
        "photos": photos,
    })
}

func extractFilePath(url string) string {
    parts := strings.Split(url, "/letter-photos/")
    if len(parts) == 2 {
        return parts[1]
    }
    return ""
}

func deleteFromSupabaseStorage(bucket, path string) error {
    url := fmt.Sprintf(
        "%s/storage/v1/object/%s/%s",
        os.Getenv("SUPABASE_URL"),
        bucket,
        path,
    )

    req, err := http.NewRequest(http.MethodDelete, url, nil)
    if err != nil {
        return err
    }

    req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_SERVICE_ROLE_KEY"))

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 && resp.StatusCode != 204 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf(
            "erro ao deletar arquivo (%d): %s",
            resp.StatusCode,
            string(body),
        )
    }

    return nil
}


func (h *Handler) DeleteLetter(c *gin.Context) {
    letterID := c.Param("id")

    // 1️⃣ Buscar URLs das fotos da carta
    rows, err := h.DB.Query(`
        SELECT photo_url
        FROM letter_photos
        WHERE letter_id = $1
    `, letterID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao buscar fotos"})
        return
    }
    defer rows.Close()

    var paths []string

    for rows.Next() {
        var url string
        if err := rows.Scan(&url); err != nil {
            c.JSON(500, gin.H{"error": "Erro ao ler fotos"})
            return
        }

        path := extractFilePath(url)
        if path != "" {
            paths = append(paths, path)
        }
    }

    log.Println("🧪 TESTE → Paths encontrados:", paths)

    // 2️⃣ Apagar arquivos do Supabase Storage (SOMENTE os dessa carta)
    for _, path := range paths {
        err := deleteFromSupabaseStorage("letter-photos", path)
        if err != nil {
            log.Println("❌ Erro ao deletar imagem:", path, err)
            c.JSON(500, gin.H{"error": "Erro ao deletar imagem do storage"})
            return
        }

        log.Println("🧹 Imagem deletada do storage:", path)
    }

    // 3️⃣ Apagar registros das fotos no banco
    _, err = h.DB.Exec(
        `DELETE FROM letter_photos WHERE letter_id = $1`,
        letterID,
    )
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao deletar fotos"})
        return
    }

    // 4️⃣ Apagar carta
    res, err := h.DB.Exec(
        `DELETE FROM letters WHERE id = $1`,
        letterID,
    )
    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao deletar carta"})
        return
    }

    affected, _ := res.RowsAffected()
    if affected == 0 {
        c.JSON(404, gin.H{"error": "Carta não encontrada"})
        return
    }

    c.JSON(200, gin.H{
        "message": "Carta e fotos deletadas com sucesso",
    })
}

func (h *Handler) GetProfile(c *gin.Context) {
    userID, exists := c.Get("userId")
    if !exists {
        c.JSON(401, gin.H{"error": "Usuário não autenticado"})
        return
    }

    var profile struct {
        ID        string `json:"id"`
        Name      string `json:"name"`
        Username  string `json:"username"`
        Email     string `json:"email"`
        CreatedAt string `json:"created_at"`
        LetterQty int    `json:"letter_qty"`
    }

    query := `
        SELECT 
            u.id,
            u.name,
            u.username,
            u.email,
            u.created_at,
            (SELECT COUNT(*) FROM letters WHERE user_id = u.id) AS letter_qty
        FROM users u
        WHERE u.id = $1
    `

    err := h.DB.QueryRow(query, userID).Scan(
        &profile.ID,
        &profile.Name,
        &profile.Username,
        &profile.Email,
        &profile.CreatedAt,
        &profile.LetterQty,
    )

    if err != nil {
        c.JSON(500, gin.H{"error": "Erro ao carregar perfil"})
        return
    }

    c.JSON(200, profile)
}








