// The values used here were taken from https://hackernoon.com/diffie-hellman-explained-sort-of-5efd0467584c
// which offers an extremely reasonable representation.
//
// The Wikipedia article is good reference : https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
// However, don't get me started on the issues with the paint picture.

package main

import (
	"fmt"
	"math/big"
	//"math/rand"
)

func powBig(a, n int64) *big.Int {
	tmp := big.NewInt(a)
	res := big.NewInt(1)
	for n > 0 {
		temp := new(big.Int)
		if n%2 == 1 {
			temp.Mul(res, tmp)
			res = temp
		}
		temp = new(big.Int)
		temp.Mul(tmp, tmp)
		tmp = temp
		n /= 2
	}
	return res
}

func Alice(prime int64, base int64) *big.Int {
	number1 := powBig(base, alices_secret_number)
	number2 := big.NewInt(prime)
	answer := big.NewInt(0)
	answer.Mod(number1, number2)
	//fmt.Printf("\nbase to the power secretnumber = (%v ** %v) = %v", base, alices_secret_number, number1)
	fmt.Printf("\nPrime: %v", number2)
	fmt.Printf("\nAnswer: %v", answer)
	return answer
}

func Bob(prime int64, base int64) *big.Int {
	number1 := powBig(base, bobs_secret_number)
	number2 := big.NewInt(prime)
	answer := big.NewInt(0)
	answer.Mod(number1, number2)
	//fmt.Printf("\nbase to the power secretnumber = (%v ** %v) = %v", base, bobs_secret_number, number1)
	fmt.Printf("\nPrime: %v", number2)
	fmt.Printf("\nAnswer: %v", answer)
	return answer
}

func AliceGetBobSecret(bobanswer int64, prime int64) {
	number1 := powBig(bobanswer, alices_secret_number)
	number2 := big.NewInt(prime)
	bobs_secret := big.NewInt(0)
	bobs_secret.Mod(number1, number2)
	fmt.Printf("\nHi, this is Alice.  Shared Secret number is %v\n", bobs_secret)

}

func BobGetAliceSecret(aliceanswer int64, prime int64) {
	number1 := powBig(aliceanswer, bobs_secret_number)
	number2 := big.NewInt(prime)
	alices_secret := big.NewInt(0)
	alices_secret.Mod(number1, number2)
	fmt.Printf("\nHi, this is Bob. Shared Secret number is %v\n", alices_secret)
}

var alices_secret_number, bobs_secret_number, prime, base int64

func main() {
	alices_secret_number = 8249 // note, not a prime.  It is divisible by 73.
	bobs_secret_number = 6531

	// alices_secret_number = int64(rand.Int31())
	// Alice, or Bob, decides on a base number, and selects a random prime number.
	// Then, one sends them both to the other.
	prime = 17
	//prime = 2833
	// prime = 9999999900000001 // Needs to be < 9223372036854775807

	base = 3667
	// base = 9
	// Now, we need to work out another number to send across as well.
	// This number is the result of raising a secret number (never transmitted!) that only
	// the sender knows to the other.  The number that is sent is arrived at by the following
	// maths: raise the base number to the power of the secret number, divide the answer
	// from that by the prime number, and the leftover/remainder is the answer to be sent.
	ToBob := Alice(prime, base)
	ToAlice := Bob(prime, base)
	//Bob(prime, base)
	fmt.Printf("\nAlice sends to Bob: %v\n", ToBob)
	fmt.Printf("\nBob sends to Alice: %v\n", ToAlice)
	//
	// At this point, Bob Knows: Prime, Base, HIS Secret Exponent, and the "Answer" value
	//              Alice Knows: Prime, Base, HER Secret Exponent, and the "Answer" value.
	//
	// Anyone observing the traffic here would know:
	//                Eve Knows: Prime, Base, Answer value.
	//
	// Concentrate, here's the magic :-)
	//
	// Take the answer you recieve.  Using your secret number, raise the answer to the power of your secret.
	// Then, divide the answer using the shared prime number.  The result is the shared secret to be used.
	//
	// First, convert from our big number to a little'r number :-)
	ToAliceLittle := ToAlice.Int64()
	AliceGetBobSecret(ToAliceLittle, prime)

	ToBobLittle := ToBob.Int64()
	BobGetAliceSecret(ToBobLittle, prime)

}
