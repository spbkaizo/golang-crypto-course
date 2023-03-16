// See: http://jspring.cs.herts.ac.uk/RSA.pdf

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	// "crypto/sha512"
	"fmt"
	// "math"
)

func banner(i int) {
	var x int
	fmt.Println()
	for x = 0; x < i; x++ {
		fmt.Printf("*")
	}
	fmt.Println()
}

func makemesomekeys(keybits int) (rsakey *rsa.PrivateKey) {
	banner(180)
	fmt.Printf("\n\n")
	rng := rand.Reader // used to get some entropy

	/*
		type PrivateKey struct {
			PublicKey            // public part.
			D         *big.Int   // private exponent
			Primes    []*big.Int // prime factors of N, has >= 2 elements.
		}
	*/

	key, err := rsa.GenerateKey(rng, keybits)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("\t\tGenerate a %v bit RSA Key\n\n\n", keybits)
	fmt.Printf("Public Modulus = %v\n\n", key.PublicKey.E) // Yet to see one that's not == 65537
	fmt.Printf("Private Exponent = %v\n\n", key.D)
	fmt.Printf("Public Number = %v\n\n", key.PublicKey.N)
	for x, _ := range key.Primes {
		fmt.Printf("Private Key Prime = %v\n\n", key.Primes[x])
	} // we only have two primes in this key... but we could have more :-)
	fmt.Printf("1st Half of the Public key should be Prime1(%v) * Prime 2(%v) = %v\n\n", key.Primes[0], key.Primes[1], key.PublicKey.N)
	fmt.Printf("2nd Half of the Public key is the Public Exponent, %v\n\n", key.PublicKey.E)
	banner(180)
	return key
}

func EncMessage(key rsa.PublicKey, message []byte) (encmessage []byte) {
	// There are two methods you can use to encrypt using an RSA key.
	// PKCS1v15 is the "standard", and whilst widely used - ignore it.
	// GIS' position is that it's fine - but you should seek to use OAEP.
	// OAEP is the newer version - and this is what we should and will use.

	// OAEP also allows for "labels".  You won't see them often (read: never)
	// but they can be remarkably useful to you.  The label parameter may
	// contain arbitrary data that will not be encrypted, but which gives
	// important context to the message.
	label := []byte("swizzle")

	rng := rand.Reader // we need some random to ensure message uniqueness

	// NOTE:
	// The message must be no longer than the length of the public modulus
	// minus twice the hash length, minus a further 2.

	encmessage, err := rsa.EncryptOAEP(sha256.New(), rng, &key, message, label)
	if err != nil {
		fmt.Println(err)
	}
	return encmessage
}

func SignMessage(key *rsa.PrivateKey, message []byte) (signature []byte) {
	// A message needs signing by a private key.  Note though, we generally
	// should only sign short messages.  In reality, it's far better to hash
	// the message using sha256 for example - and then sign that hash.
	newhash := sha256.New()
	newhash.Write(message)
	hashed := newhash.Sum(nil)
	fmt.Printf("\n\nSha256 of message : %x\n", hashed)
	//
	// Note we don't necessarily need to encrypt messages - sometimes we just
	// need to be able to authenticate them.
	//
	// Also, there's always `lively' discussion on if you should :
	// MAC then Encrypt - or
	// Encrypt then MAC.
	// See https://www.google.co.uk/search?q=mac+then+encrypt+or+encrypt+then+mac
	// ("I am a bit perplexed by the fact that this question seems highly related
	//  to crypto.stackexchange.com/questions/5458/…, but has diametrically
	//  opposed answers")
	//
	// Note, just like the encryption above, there are two main supported methods
	// for signing messages - PSS (aka RSASSA-PSS) and PKCS1v15(aka RSA PKCS#1 v1.5).
	//
	// For now - just accept that PSS is the new kid in town, and recommended
	// to be used *unless* you have to use the other.
	rng := rand.Reader // again, we need some random to throw into the mix!
	signature, err := rsa.SignPSS(rng, key, crypto.SHA256, hashed, nil)
	if err != nil {
		fmt.Printf("ERROR: %v", err)
	}
	return signature

}

func DecMessage(key *rsa.PrivateKey, encmessage []byte) (clearmessage []byte) {
	label := []byte("swizzle")
	rng := rand.Reader
	clearmessage, err := rsa.DecryptOAEP(sha256.New(), rng, key, encmessage, label)
	if err != nil {
		fmt.Println(err)
	}
	return clearmessage
}

func VerifyMessage(key *rsa.PublicKey, message []byte, signature []byte) (ok bool) {
	// To verify the message, we need the message itself (this can be either
	// encrypted, or in clear - we just don't care) and to verify, we do the
	// following:
	//
	// 1. hash the original message to derive the result of it
	// 2. Pass the hash to the verification process.
	// 3. This function then checks that they are equivalent, if not then something's
	//    amiss!
	newhash := sha256.New()
	newhash.Write(message)
	hashed := newhash.Sum(nil)
	//
	// Now, verify that the signature hash matches the original!
	err := rsa.VerifyPSS(key, crypto.SHA256, hashed, signature, nil)
	if err == nil {
		return true
	} else {
		fmt.Printf("SIGNATURE TAMPERED WITH: %v", err)
		return false
	}
}

func main() {
	// See http://sergematovic.tripod.com/rsa1.html
	// and https://www.cs.colorado.edu/~srirams/courses/csci2824-spr14/rsa-13.html
	//
	// For now though,
	// Suppose Alice wished to send a message M to Bob that she wished Bob and no one else to read.
	// In a public key system, she will obtain Bob's public key and encrypt the message M using Bob's public key to obtain a encrypted message c.
	// This is sent to Bob.
	// Upon receiving the message from Alice, Bob decrypts it using his private key.
	// No one else can decrypt the message unless they have Bob's private key.
	//
	// RSA is a "one-way" function.  Given c and publickKey, it should not possible to *easily* compute M.
	//
	// The basic scheme for RSA uses a really large number n.
	// The public key is a pair of numbers (e,n)
	// The private key is a pair of numbers (d,n).

	// Alice and Bob.  And Eve.  https://xkcd.com/177/
	// History: http://cryptocouple.com/ & https://en.wikipedia.org/wiki/Alice_and_Bob
	alice := makemesomekeys(768)
	bob := makemesomekeys(768)

	fmt.Printf("\nAlice: %v\n", alice)
	fmt.Printf("\nBob: %v\n", bob)

	//eve := makemesomekeys(4096)
	//fmt.Printf("\nEve: %v\n", eve)

	/*
		PublickKey is part of an RSA keypair.  In reality, these are again - just numbers...

		type PublicKey struct {
			N *big.Int // modulus
			E int      // public exponent
		}
	*/
	//alicepub := alice.PublicKey
	bobpub := bob.PublicKey

	message := []byte("this is top secret")
	/*
		fmt.Printf("Clear text Message : %v\n", message)
		fmt.Printf("alice pub : %v\n", alicepub)
		fmt.Printf("bob pub : %v\n", bobpub)

		bobtoalicemessage := EncMessage(alicepub, message)
		fmt.Printf("Bob to Alice Message: %v\n", bobtoalicemessage)


		// `bobtoalicemessage' is now an encrypted message, utterly useless even to the sender at this point.
		// However, alice can use her private key to decrypt it...
		alicesmessage := DecMessage(alice, bobtoalicemessage)
		fmt.Printf("Decrypted Message : %v\n", string(alicesmessage))
	*/

	bobsig := SignMessage(bob, message)
	fmt.Printf("Bobs Signature in Hex: %x\n", bobsig)

	goodsig := VerifyMessage(&bobpub, message, bobsig)
	if goodsig == true {
		fmt.Printf("Good signature!")
	}

}
