package main

import (
	"fmt"
	"log"

	"github.com/lambda-mena/criptografia-rsa/internal"
)

func main() {
	log.Println("Criptografia-Rsa v1.0")
	log.Println("Generando Llaves...")
	internal.GenerateKeyPairs()

	for {
		var option int
		log.Println("Opciones: 1) Encriptar Mensaje 2) Desencriptar Mensaje 3) Salir")
		fmt.Scanln(&option)

		if option == 1 {
			encryptMessage()
		} else if option == 2 {
			decryptMessage()
		} else if option == 3 {
			break
		}
	}
}

// Función del CLI para encriptar un mensaje con llave publica.
func encryptMessage() {
	var publicKey string
	var rawMessage string
	log.Print("Digite el mensaje a encriptar: ")
	fmt.Scan(&rawMessage)
	log.Print("Digite la llave publica con la cual encriptara: ")
	fmt.Scan(&publicKey)
	internal.EncryptMessage(publicKey, rawMessage)
}

// Función del CLI para desencriptar un mensaje con llave privada.
func decryptMessage() {
	var cipheredMessage string
	log.Print("Digite el mensaje a desencriptar: ")
	fmt.Scan(&cipheredMessage)
	internal.DecryptMessage(cipheredMessage)
}
