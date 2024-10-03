package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/lambda-mena/criptografia-rsa/internal/crypto"
)

var scanner = bufio.NewScanner(os.Stdin)

func main() {
	log.Println("Criptografia-Rsa v1.0")
	log.Println("Generando Llaves...")
	crypto.GenerateKeyPairs()

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

// Función para leer la entrada de la terminal
func scanConsole() string {
	scanner.Scan()
	return scanner.Text()
}

// Función del CLI para encriptar un mensaje con llave publica.
func encryptMessage() {
	log.Print("Digite el mensaje a encriptar: ")
	rawMessage := scanConsole()
	log.Print("Digite la llave publica con la cual encriptara: ")
	public := scanConsole()
	crypto.EncryptMessage(public, rawMessage)
}

// Función del CLI para desencriptar un mensaje con llave privada.
func decryptMessage() {
	log.Print("Digite el mensaje a desencriptar: ")
	cipheredMessage := scanConsole()
	crypto.DecryptMessage(cipheredMessage)
}
