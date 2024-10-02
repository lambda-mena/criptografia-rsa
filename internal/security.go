package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
)

var privateKey *rsa.PrivateKey
var publicKey rsa.PublicKey

// Función para generar las llaves que se usaran para encripción.
func GenerateKeyPairs() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		log.Fatalf("Error al generar llaves...")
	}

	publicKey = privateKey.PublicKey
	// Imprime la información de tu llave privada
	log.Println("--- LLAVE PRIVADA ---")
	log.Println("P y Q -->", privateKey.Primes)
	log.Println("N -->", privateKey.N)
	log.Println("D -->", privateKey.D)
	log.Println("--- FIN PRIVADA ---")
	// Imprime la llave publica para que la envies a la persona con la que desees hablar
	log.Println("--- LLAVE PUBLICA ---")
	log.Println("E y N -->", fmt.Sprintf("(%d, %s)", publicKey.E, publicKey.N))
	log.Println("--- FIN PUBLICA ---")
}

// Función de lógica para encriptar
func EncryptMessage(publicModulus *big.Int, rawMessage string) {
	var public rsa.PublicKey
	public.E = 65537
	public.N = publicModulus
	log.Println("Llave publica digitada:", fmt.Sprintf("(%d, %s)", public.E, public.N))

	rng := rand.Reader
	cip, err := rsa.EncryptOAEP(sha256.New(), rng, &privateKey.PublicKey, []byte("Hola"), []byte("q"))
	if err != nil {
		log.Fatal("Error:", err)
	}
	log.Println(cip)

	var cipheredMessage strings.Builder
	for idx, rawChar := range rawMessage {
		leftOperand := big.NewInt(0)
		leftOperand.Exp(big.NewInt(int64(rawChar)), big.NewInt(int64(public.E)), nil)
		cipheredChar := big.NewInt(0)
		cipheredChar.Mod(leftOperand, public.N)

		if idx+1 == len(rawMessage) {
			cipheredMessage.WriteString(cipheredChar.String())
		} else {
			cipheredMessage.WriteString(cipheredChar.String() + "/")
		}
	}

	log.Println("Base64:", base64.NewEncoding(cipheredMessage.String()))
	log.Println("Mensaje encriptado:", cipheredMessage.String())
}

// Función de lógica para desencriptar
func DecryptMessage(cipheredMessage string) {
	var plainText strings.Builder
	dividedArrayBytes := splitArrayBytes([]byte(cipheredMessage))
	for _, byteArray := range dividedArrayBytes {
		num, err := strconv.Atoi(string(byteArray))
		if err != nil {
			log.Println("No se pudo convertir el arreglo de bytes a numero.")
		}
		result := big.NewInt(int64(num))
		result = result.Exp(result, privateKey.D, nil)
		result = result.Mod(result, privateKey.N)
		fmt.Println("Caracter:", result.Int64())
		ascii := rune(result.Int64())
		plainText.WriteRune(ascii)
	}

	fmt.Println("Mensaje:", plainText.String())
}

func splitArrayBytes(content []byte) [][]byte {
	return bytes.Split(content, []byte("/"))
}
