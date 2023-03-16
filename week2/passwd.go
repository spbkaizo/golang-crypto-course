// For the gory details, see https://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf

package main

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func main() {
	// By far and away, the best documentation for UNIX internals is the excellent set produced
	// by the OpenBSD project.  It's also the best UNIX environment for learning about true
	// UNIX systems in the authors opinion.  It no longer supports the original crypt, but the older
	// versions did :-)
	// https://man.openbsd.org/OpenBSD-2.2/crypt.3 (2.2 was released sometime around December 1, 1997)

	password := "averylongpassword123"
	key := password[:8]
	mysalt := password[:2]
	fmt.Printf("Chopped password %v to make key %v, with %v being the salt.", password, key, mysalt)
	fmt.Printf("\nHex password : %x & Salt : %x", password, mysalt)

	/*
		coerce to 8 bytes.  This gives us 64 bits.
		DES however users 56 (or 40, if not in the US previously...)

		See http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm for a run through,
		but for now - just accept that the 8bit is discarded from each byte, and then each bit is swapped
		around according to a predefined table, multiple times.  One such table is shown below.

		(Ref: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm)


		               PC-1

		   57   49    41   33    25    17    9
		    1   58    50   42    34    26   18
		   10    2    59   51    43    35   27
		   19   11     3   60    52    44   36
		   63   55    47   39    31    23   15
		    7   62    54   46    38    30   22
		   14    6    61   53    45    37   29
		   21   13     5   28    20    12    4
	*/
	desblock, err := des.NewCipher([]byte(key)) // Trust that the implementation will deal with converting the original 64bits -> 56bits, the magic swapping and the derivation of all the keys...
	if err != nil {
		fmt.Println(err)
	}
	// Next we encrypt an all zeros' block using this key.
	zeroblock := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	var output []byte
	mode := cipher.NewCBCEncrypter(desblock, desblock)
	desblock.Encrypt(zeroblock, output)
	fmt.Printf("%x", output)

}
