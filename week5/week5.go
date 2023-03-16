package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	//"encoding/hex"
	"encoding/pem"
	"fmt"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func checkerr(err error) {
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
}

func main() {
	rsaprivkey, err := rsa.GenerateKey(rand.Reader, 64)
	checkerr(err)
	fmt.Printf("Private Key: %v\n", rsaprivkey)

	// Now we need to save our private key.  All we currently have is some numbers :-)

	// Keys, are first converted to an ASN.1 structure.  Pretend it doesn't exist.  Trust me on this.
	// Fun Fact: The Linux Kernel has 5 separate ASN.1 parsers (https://www.x41-dsec.de/de/lab/blog/kernel_userspace/)
	keybytes := x509.MarshalPKCS1PrivateKey(rsaprivkey)
	//fmt.Printf("ASN1 Key Bytes: %v\n", string(keybytes))
	//fmt.Printf("ASN1 Key Hex: %v\n", hex.EncodeToString(keybytes))
	fmt.Printf("ASN1 Key Base64: %v\n", base64.StdEncoding.EncodeToString(keybytes))
	// If you really want to see what this is, paste the above Base64 encoded value into https://lapo.it/asn1js
	//
	// So, we now have an RSA private key, that's encoded into a byte array using PKCS1 ( Public-Key Cryptography Standards #1 ).
	// This byte array is stored using Base64 encoding, and we can store this encoded version into a standard file format.
	//
	// Let's use PEM data encoding, which originated in Privacy Enhanced Mail.
	// The most common use of PEM encoding today is in TLS keys and certificates. See RFC 1421.
	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaprivkey),
	}

	encodedkey := pem.EncodeToMemory(privateKey)
	fmt.Printf("Encoded Key: \n%v\n", string(encodedkey))

	// Question is - what's a PEM block contain...?
	/*
		type Block struct {
			Type    string            // The type, taken from the preamble (i.e. "RSA PRIVATE KEY").
			Headers map[string]string // Optional headers.
			Bytes   []byte            // The decoded bytes of the contents. Typically a DER encoded ASN.1 structure.
		}
	*/
	var headers = make(map[string]string)
	headers["hello"] = "goodbye"
	headers["name"] = "Brett"
	var privateKey2 = &pem.Block{
		Type:    "THIS IS NOT THE KEY YOU ARE LOOKING FOR",
		Bytes:   x509.MarshalPKCS1PrivateKey(rsaprivkey),
		Headers: headers,
	}
	encodedkey2 := pem.EncodeToMemory(privateKey2)
	fmt.Printf("Encoded Key: \n%v\n", string(encodedkey2))

	// OK, so now we've got two keys - that just exist in clear.  However, there's a
	// standard mechanism to encrypt these at rest, defined in the RFC's.
	//
	privateKey3, err := x509.EncryptPEMBlock(rand.Reader, privateKey.Type, privateKey.Bytes, []byte("secret"), x509.PEMCipherAES256)
	checkerr(err)
	encodedkey3 := pem.EncodeToMemory(privateKey3)
	fmt.Printf("Encrypted Key:  \n%v\n", string(encodedkey3))

	// CBC mode & IV's

}
