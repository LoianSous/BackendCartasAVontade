
package models

type RegisterRequest struct {
    Name     string `json:"name" binding:"required"`
    Username string `json:"username" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
    Identifier string `json:"identifier" binding:"required"` 
    Password   string `json:"password" binding:"required"`
}

type RecoverEmailRequest struct {
    Email string `json:"email" binding:"required,email"`
}

type RecoverVerifyRequest struct {
    Email string `json:"email" binding:"required,email"`
    Code  string `json:"code" binding:"required"`
}

type ResetPasswordRequest struct {
    Email       string `json:"email"`
    NewPassword string `json:"newPassword"`
}

//O request serve para definir o modelo de dados para o frontend, que o banco de dados exige.

type CreateLetterRequest struct {
    LetterTitle      string `json:"letter_title"`
    BelovedName      string `json:"beloved_name"`
    Birthday         string `json:"birthday"`
    FavoriteColor    string `json:"favorite_color"`
    Compliment       string `json:"compliment"`
    FromName         string `json:"from_name"`
    ToName           string `json:"to_name"`
    SpecialMessages  string `json:"special_messages"`
    TimeTogether     string `json:"time_together"`
    FavoriteMovie    string `json:"favorite_movie"`
    FavoriteFood     string `json:"favorite_food"`
    ZodiacSign       string `json:"zodiac_sign"`
    ThingsTheyLike   string `json:"things_they_like"`
    TemplateID       int   `json:"template_id"`
    UserID           string `json:"user_id"`
    ShareURL         string `json:"share_url"`
}

type CreateLetterPhotoRequest struct {
    LetterID int    `json:"letter_id" binding:"required"`
    PhotoURL string `json:"photo_url" binding:"required"`
}