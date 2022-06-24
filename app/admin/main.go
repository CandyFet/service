package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

/*
	openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in private.pem -out public.pem
*/

func main() {
	keygen()
	tokenGen()
}

func tokenGen() {
	privatePEM, err := ioutil.ReadFile("/Users/candyfet/study/ardanlab/service/private.pem")
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		log.Fatalln(err)
	}

	// Generating a token requires a set pf claims. In this applications
	// case, we only care about defining the subject and the user in question and
	// the roles they have on the database. This token will expire in a year.
	//
	// iss (issuer): Issuer of the JWT
	// sub (subject): Subject of the JWT (the user)
	// aud (audience): Recipient for which the JWT expires
	// exp (expiration time): Time after which the JWT expires
	// nbf (not before time): Time before which the JWT must not be accepted for processing
	// iat (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT
	// jti (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed
	claims := struct {
		jwt.StandardClaims
		Roles []string `json:"roles"`
	}{
		StandardClaims: jwt.StandardClaims{
			Issuer:    "service project",
			Subject:   "123456789",
			ExpiresAt: time.Now().Add(87600 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		Roles: []string{"ADMIN"},
	}

	method := jwt.GetSigningMethod("RS256")
	tkn := jwt.NewWithClaims(method, claims)
	tkn.Header["kid"] = "d8420866-1615-43d3-9a25-928120080b8f"

	str, err := tkn.SignedString(privateKey)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("-----BEGIN TOKEN-----\n%s\n-----END TOKEN-----\n", str)
}

func keygen() {
	// Generate a new private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalln(err)
	}

	// Create a file for the private key information in PEM form.
	privateFile, err := os.Create("private.pem")
	if err != nil {
		log.Fatalln(err)
	}
	defer privateFile.Close()

	// Construct a PEM block for the private key.
	privateBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Write rhe private key to the private key file.
	if err := pem.Encode(privateFile, &privateBlock); err != nil {
		log.Fatalln(err)
	}

	// ==========================================================================

	// Marshal the public key from the private key to PKIX.
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalln(err)
	}

	// Create a file for the public key information in PEM form.
	publicFile, err := os.Create("public.pem")
	if err != nil {
		log.Fatalln(err)
	}
	defer publicFile.Close()

	// Construct a PEM block for the public key.
	publicBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	// Write the public key to the private key file.
	if err := pem.Encode(publicFile, &publicBlock); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("DONE")
}
