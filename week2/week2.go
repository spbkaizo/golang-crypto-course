package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"io/ioutil"
	"strings"
)

func cksum(s string) {
	var checksum int
	for i := 0; i < len(s); i++ {
		// It's important to note here - we are not simply adding numbers -
		// we are fundamentally changing them using them using the bits they have.
		// e.g. the following operations produce the following results...
		// 1001 (9)  AND 0110 (6) = 0000 (0)
		// 1001 (9)  OR  0110 (6) = 1111 (8+4+2+1 == 15)
		// 1001 (9)  XOR 0110 (6) = 1111 (8+4+2+1 == 15)
		// 1111 (15) XOR 0110 (6) = 1001 (8+0+0+1 == 9)
		checksum = (checksum >> 1) + ((checksum & 1) << 15)
		fmt.Printf("\nChar is:%v and in binary is %b, and as a number: %v.  Checksum was %v. ", string(s[i]), s[i], s[i], checksum)
		checksum += int(s[i])
		checksum &= 0xffff /* Keep it within bounds. */
		fmt.Printf("After adding it all together, checksum is now :%v", checksum)
	}
	fmt.Printf("\n\nFINAL Checksum: %v (hex: %x)\n", checksum, checksum)
}

func md5hash() []byte {
	// MD5 hashes work, like other hashes, on the principle of read a chunk of data (512bits/64 bytes),
	// compute the hash of that data, AND(and, actually XOR, and OR...)  that with the last computed hash, goto next.
	//
	// Another very important point is that changing a single bit results in an entirely
	// different hash, see https://en.wikipedia.org/wiki/Avalanche_effect for details.
	//
	// The speed of generation of hashes, on modern kit, is astounding.
	// An NVIDIA GeForce 8800 Ultra can calculate more than 200,000,000 hashes per second.
	h := md5.New()
	io.WriteString(h, "The fog is getting thicker!")
	io.WriteString(h, "An Leon's getting laaarger!.")
	return h.Sum(nil)
}

func md5hashfile(filename string) []byte {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	h := md5.New()
	h.Write(bytes)
	hash := h.Sum(nil)
	return hash
}

func sha3test(filename string) []byte {
	// SHA-2 is essentially a security patch of SHA-1.
	//
	// "SHA-1 and SHA-2 NIST standard hash functions were designed behind closed doors at NSA.
	//
	// The standards were put forward in 1995 and 2001 respectively, without public scrutiny
	// of any significance, despite the fact that at time of publication there was already
	// a considerable cryptographic community doing active research on this subject"
	// (See: https://en.wikipedia.org/wiki/SHA-3)
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	hash := make([]byte, 64)
	sha3.ShakeSum256(hash, bytes)
	return hash
}

func md5pad(filename string) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
	}
	randbytes := make([]byte, 16) // arbitarily chosen.  Should give us enough results.
	for {
		_, err = rand.Read(randbytes)
		var newbytes []byte
		newbytes = append(bytes, randbytes...)
		h := md5.New()
		h.Write(newbytes)
		hash := h.Sum(nil)
		dst := make([]byte, hex.EncodedLen(len(hash)))
		hex.Encode(dst, hash)
		// fmt.Printf("\n%v", string(dst))
		if strings.HasPrefix(string(dst), "c0ffee") == true {
			if strings.Contains(string(dst), "cafe") == true {
				fmt.Printf("\n%v", string(dst))
				_ = ioutil.WriteFile(string(dst), newbytes, 0700)
			}
		}

	}
}

func main() {
	/*
		var x uint = 23
		var y int = -23
		fmt.Printf("my int is %b/%v, my uint is %b/%v\n", x, x, y, y)
		x = x << 2 // equivalent to x * 4
		y = y >> 1
		fmt.Printf("my int is %b/%v, my uint is %b/%v\n", x, x, y, y)
		//
		// &    bitwise AND
		// is the equivalent to
		var n, p int
		n = 9
		p = 8
		fmt.Printf("\n N=%b, P=%b", n, p)
	*/

	// cksum("okchecksumthis123")
	hash := md5hash()
	fmt.Printf("\n%x\n", hash)
	hash = md5hashfile("1MBfile")
	fmt.Printf("\n%x\n", hash)

	hash = sha3test("1MBfile")
	fmt.Printf("\n%x\n", hash)
	//md5pad("ls")

}
