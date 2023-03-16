package main

// This week, the wonderful world of ASN.1 / DER-encoded ASN.1 data structures, as defined in ITU-T Rec X.690.

// Abstract Syntax Notation.One (ASN.1) is an interface description language for defining data structures that
// can be serialized and deserialized in a standard, cross-platform way. It's broadly used in telecommunications
// and computer networking, and especially in cryptography.

// ASN.1 is used in X.509, which defines the format of certificates used in the HTTPS protocol for securely
// browsing the web, and in many other cryptographic systems.

import (
	"crypto/rsa"
	// "encoding/asn1"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

func makemesomekeys(keybits int) (rsakey *rsa.PrivateKey) {
	rng := rand.Reader // used to get some entropy
	key, err := rsa.GenerateKey(rng, keybits)
	if err != nil {
		fmt.Println(err)
	}
	return key
}

func main() {
	rsakey := makemesomekeys(16)
	// MarshalPKCS1PrivateKey Shovels an RSA private key in, and returns some bytes encoded using ASN1 notatation.
	asn1bytes := x509.MarshalPKCS1PrivateKey(rsakey)
	// Those bytes, are essentially useless to us now.  So let's unpack them...
}
