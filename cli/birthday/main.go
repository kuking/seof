package main

import (
	"fmt"
	"math"
	"math/big"
)

// The following calculates the probability of duplicating a nonce when picked at random (as the current implementation
// does). The current implementation uses 3 nonces of 12 bytes each (for each AES256/GCM cipher).
//
// The birthday problem is calculated for one nonce of 12 bytes (96 bits).
//
// After 100M nonces, the probability is:
// 100M, 0.999999999999936891126951232322755154461737176572294203867910474082896986505554273464571044238582672950519...
// or 13 decimal places, 100M writes using 1K blocks equals to writing 95 GiB
//
// 1000M, 0.99999999999368911275194093196384046656288207084848697587501906334095744742126709550393559064875913479644...
// or 11 decimal places. after writing 950 GiB.
//
// if you consider after breaking the first layer of AES256/GCM, there are another two more layers to go...
// If we assume a whole file is written only once, an attacker can scan for duplicated two nonce in it, in practice
// the blocks will be overwritten and the nonce replaced with new ones, an attacker will have to capture every byte
// written to get a better chance of capturing two equal nonce.

func main() {
	const prec = 1000   // bits
	const bits = 12 * 8 // the first nonce for the first AES256
	const n = 1_000_000_000_000

	days := big.NewFloat(math.Pow(2, bits))

	fmt.Printf("Days: %.0f\n", days)
	fmt.Printf("N: %v\n", n)

	p := new(big.Float).SetPrec(prec).SetInt64(1)

	work := new(big.Float).SetPrec(prec)
	iFlt := new(big.Float).SetPrec(prec)
	one := new(big.Float).SetPrec(prec).SetInt64(1)
	for i := 0; i < n; i++ {
		// p *= (days - i) / days
		work.Sub(days, iFlt)
		work.Quo(work, days)
		p.Mul(p, work)
		iFlt.Add(iFlt, one)
		if i%1_000_000 == 0 {
			fmt.Printf("%vM, %.200f\n", i/1000/1000, p)
		}
	}
	fmt.Printf("%.100f\n", p)
}
