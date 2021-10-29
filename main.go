package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"os"
	"strings"

	"github.com/atotto/clipboard"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func EncodePublicKeyToMemory(pubkey *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)})
}

func EncodePrivateKeyToMemory(privkey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privkey)})
}

func askToCopy(message, content string) {
	print(message)
	res, err := bufio.NewReader(os.Stdin).ReadString('\n')
	must(err)
	if strings.TrimSpace(res) != "n" {
		must(clipboard.WriteAll(content))
	}
}

func main() {
	bits := flag.Int("-s", 2048, "Size of the keys")
	flag.Parse()
	privKey, err := rsa.GenerateKey(rand.Reader, *bits)
	must(err)

	pubKey := &privKey.PublicKey

	pubKeyString := EncodePublicKeyToMemory(pubKey)
	privKeyString := EncodePrivateKeyToMemory(privKey)
	must(os.WriteFile("./public.pem", pubKeyString, 0644))
	must(os.WriteFile("./private.pem", privKeyString, 0644))
	println("Both keys saved as pem files")

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyString)
	askToCopy("Enter to copy public key to clipboard or enter \"n\" to skip:", pubKeyB64)
	privKeyB64 := base64.StdEncoding.EncodeToString(privKeyString)
	askToCopy("Enter to copy private key to clipboard or enter \"n\" to skip:", privKeyB64)
}
