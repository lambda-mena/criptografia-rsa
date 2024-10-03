package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"math/big"
	"strings"

	"github.com/lambda-mena/criptografia-rsa/utils"
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
	log.Println("--- PAR DE LLAVES ---")
	//log.Println("P y Q -->", privateKey.Primes)
	//log.Println("N -->", privateKey.N)
	//log.Println("D -->", privateKey.D)
	log.Println("LLAVE PRIVADA ->", encodeToBase64(privateKey.D.Bytes()))
	// Imprime la llave publica para que la envies a la persona con la que desees hablar
	//log.Println("E y N -->", fmt.Sprintf("(%d, %s)", publicKey.E, publicKey.N))
	log.Println("LLAVE PUBLICA ->", encodeToBase64(publicKey.N.Bytes()))
	log.Println("--- FIN LLAVES ---")
}

// Función para codificar en base64
func encodeToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// Función para decodificar en base64
func decodeToBase64(key string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal("Error al decodificar la llave...")
	}
	return decoded
}

// Función de lógica para encriptar
func EncryptMessage(publicKey string, rawMessage string) {
	var public rsa.PublicKey
	public.E = 65537
	public.N = big.NewInt(0).SetBytes(decodeToBase64(publicKey))

	var cipheredMessage []byte
	for _, rawChar := range rawMessage {
		result := big.NewInt(0)
		result.Exp(big.NewInt(int64(rawChar)), big.NewInt(int64(public.E)), public.N)
		cipheredMessage = append(cipheredMessage, result.Bytes()...)
	}

	log.Println("Mensaje encriptado:", encodeToBase64(cipheredMessage))
}

// Función de lógica para desencriptar
func DecryptMessage(cipheredMessage string) {
	var plainText strings.Builder
	dividedArrayBytes := utils.ChunkBy(decodeToBase64(cipheredMessage), 32)
	for _, byteArray := range dividedArrayBytes {
		result := big.NewInt(0).SetBytes(byteArray)
		result = result.Exp(result, privateKey.D, privateKey.N)
		ascii := rune(result.Int64())
		plainText.WriteRune(ascii)
	}

	log.Println("Mensaje:", plainText.String())
}
