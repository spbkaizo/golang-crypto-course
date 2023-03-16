package main

import (
	//"crypto/cipher" // contains xor
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

//  00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18
//   m  a  r  y  h  a  d  a  l  i  t  t  l  e  l  a  m  b
//   s  h  s  h  d  o  n  t  t  e  l  l  a  n  y  o  n  e
var plaintext = "maryhadalittlelamb"
var ciphertext string
var keystring = "shshdonttellanyone" // needs to be same length as plaintext for this demo

var txkey byte = '!'

func rot13(s string) string {
	return "a"
}

func h() {
	fmt.Printf("\n")
	fmt.Println("***************************************************************************************************************")
}

// https://en.wikipedia.org/wiki/XOR_cipher
// For "correct" xor implementation, see : https://golang.org/src/crypto/cipher/xor.go
func xor(plaintext string, key string) (output string) {
	// XOR works on a bit level, and thus, on a byte level.  A string is just a printable byte :-)
	for i := 0; i < len(plaintext); i++ {
		// ^ == bitwise xor, see https://golang.org/ref/spec#Arithmetic_operators
		output += string(plaintext[i] ^ key[i%len(key)])
	}
	return output
}

func xordemo() {
	// See: https://en.wikipedia.org/wiki/Bitwise_operation
	i := big.NewInt(65)
	x := big.NewInt(66)
	// https://golang.org/pkg/math/big/#Int.Format
	fmt.Printf("\nA is %b in binary", i)
	fmt.Printf("\nB is %b in binary", x)
	foo := big.NewInt(0)
	foo.Xor(i, x)
	fmt.Printf("\nXOR A(%b) ^ B(%b): %b\n", i, x, foo)
	//foo := i ^ x
	//fmt.Printf("\nXOR is : %v", strconv.FormatInt(int64(foo), 10))
}

func printtable() {
	h()
	// https://www.cs.cmu.edu/~pattis/15-1XX/common/handouts/ascii.html
	for i := 0; i <= 255; i++ {
		// convert from octal to a string
		fmt.Printf("\nDec: %v ", i)
		fmt.Printf("Char: %v ", string(i))
		// convert to hex
		fmt.Printf("Hex: %v ", strconv.FormatInt(int64(i), 16))
		// convert to binary
		fmt.Printf("Bits: %v ", strconv.FormatInt(int64(i), 2))
		// convert to octal
		fmt.Printf("Oct: %v ", strconv.FormatInt(int64(i), 8))
	}
	h()
}

func printhex(s string) {
	h()
	for _, letter := range s {
		fmt.Printf("%v = %v(hex)\n", string(letter), strconv.FormatInt(int64(letter), 16))
	}
	h()
}

func printbits(s string) {
	h()
	for _, letter := range s {
		// strconv converts strings to number, see https://golang.org/pkg/strconv/
		fmt.Printf("%v = %v(bits)\n", string(letter), strconv.FormatInt(int64(letter), 2))
	}
}

func cracker(hexcrypt string) {
	// SS, EE, TT, and FF are the most common repeats...
	// see: https://en.wikipedia.org/wiki/Frequency_analysis
	fmt.Printf("CIPHERTEXT: %v\n", hexcrypt)
	bytes, _ := hex.DecodeString(hexcrypt)
	// an array of arrays :-)
	//password := [][]string{}
	// fmt.Printf("bytes: %v", bytes) // garbled, unprintable ciphertext...
	for x, y := range bytes {
		//fmt.Printf("%v", string(y))
		fmt.Printf("%v position char is one of: ", x)
		for i := 0; i < 255; i++ {
			// As we can assume that the user has a standard keyboard, we should assume the password
			// contains readable charectors from it.  Thus, from dec(32) to dec(126) are of interest
			//
			// This is known as the `keyspace', and we have reduced it drastically from n*256 to n*94...
			// e.g. for a 1 char password it's 1 in 94
			//      for a 2 char password it's 1 in (94*94) = 8836
			//      for a 3 char password it's 1 in (94*94*94) = 830,584
			// vs.  for a 1 char password it's 1 in 256
			//      for a 2 char password it's 1 in (256*256) = 65,535
			//      for a 3 char password it's 1 in (256*256*256) = 16,777,216
			check := i ^ int(y)
			//foo := big.NewInt(0)
			//foo.Xor(i, y)
			if (check >= 32) && (check <= 126) {
				fmt.Printf("%v", string(check))
			}

		}
		fmt.Println()
	}
}

func websphere(webspass string) {
	var webskey byte = '_'
	decoded, _ := base64.StdEncoding.DecodeString(strings.TrimLeft(webspass, "{xor}"))
	var output string
	for i := 0; i < len(decoded); i++ {
		output += string(decoded[i] ^ webskey)
	}
	fmt.Printf("WebSphere Decoded: %v", output)
}

func txamount(amount, fromaccount, toaccount string) string {
	var crypted string
	cleartextmsg := "TRANSFER GBP" + amount + " TO ACCOUNT " + toaccount + " FROM ACCOUNT " + fromaccount
	for i := 0; i < len(cleartextmsg); i++ {
		crypted += string(cleartextmsg[i] ^ txkey)
	}
	cryptedb64 := base64.StdEncoding.EncodeToString([]byte(crypted))
	return cryptedb64
}

func txamounthacked(crypted string) string {
	decoded, _ := base64.StdEncoding.DecodeString(crypted)
	// now we have the clear bytes, albeit encrypted
	// We know the first chars of the messages in the byte array are:
	// "TRANSFER £" so just repear the first number we find 3 times :-)
	// TRANSFER GBP1000 TO ACCOUNT 87654321 FROM ACCOUNT 12345678
	foo := decoded[0:12]
	rest := decoded[12:]
	foo = append(foo, decoded[12])
	foo = append(foo, decoded[12])
	foo = append(foo, decoded[12])
	foo = append(foo, rest...)
	recrypted := base64.StdEncoding.EncodeToString(foo)

	return recrypted
}

func decodetxamount(encmessage string) {
	decoded, _ := base64.StdEncoding.DecodeString(encmessage)
	var output string
	for i := 0; i < len(decoded); i++ {
		output += string(decoded[i] ^ txkey)
	}
	fmt.Printf("\nMessage is : %v\n", output)
}

func main() {
	// printtable()
	//printhex(plaintext)
	//printhex(keystring)
	//printbits(plaintext)
	//printbits(keystring)
	//		printtable()

	//xordemo()
	output := xor(plaintext, keystring)
	//fmt.Println(output) // garbage, probably...
	encodedOutput := hex.EncodeToString([]byte(output))
	fmt.Printf("Hex Encoded Message : %v\n", encodedOutput)
	output = xor(output, keystring)
	fmt.Printf("Clear: %v", output)
	cracker(encodedOutput)
	/*
		fmt.Printf("XOR again gives us: %v\n", output)
	*/
	/*
		plaintext = "maryhadalittlelamB"
		output = xor(plaintext, keystring)
		encodedOutput = hex.EncodeToString([]byte(output))
		fmt.Printf("Hex Encoded Message : %v\n", encodedOutput)
	*/
	// websphere("{xor}CDo9Hgw=")
	/*
		transaction := txamount("1000", "12345678", "87654321")
		//decodetxamount(transaction)
		hacked := txamounthacked(transaction)
		decodetxamount(hacked)
	*/

}
