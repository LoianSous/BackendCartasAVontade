package services

import (
    "crypto/rand"
    "fmt"
    "gopkg.in/gomail.v2"
)

func GenerateCode() string {
    code := make([]byte, 3)
    rand.Read(code)
    return fmt.Sprintf("%05d", int(code[0]) + int(code[1]) + int(code[2]))
}

func SendEmail(to, code string) error {
    m := gomail.NewMessage()
    m.SetHeader("From", "seuemail@gmail.com")
    m.SetHeader("To", to)
    m.SetHeader("Subject", "Código de Recuperação")
    m.SetBody("text/plain", "Seu código de recuperação é: " + code)

    d := gomail.NewDialer("smtp.gmail.com", 587, "loian9109@gmail.com", "wbim waoi hkxf odeb")

    return d.DialAndSend(m)
}
