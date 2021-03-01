package main

import (
	"fmt"
	"math"
	"math/big"
)

// The following calculates the probability of duplicating a nonce when picked at random (as the current implementation
// does). The current implementation uses 3 nonces of 12 bytes each (for each AES256/GCM cipher).
//
// The probability of picking the same nonce twice (birthday paradox) is calculated for one nonce of 12 bytes (96 bits).
//
// 100M, 0.999999999999936891126951232322755154461737176572294203867910474082896986505554273464571044238582672950519...
// lower than 0.00000000000001, or 1 in 100.000.000.000.000
// 100M blocks of 1K is approx. 95GiB written.
//
// 1258M, 0.99999999999001261703522929514448885033012604685025065706759067812784429829344821159506777018445782306879...
// lower than 0.000000000001, or  1 in 1.000.000.000.000
// 1258M blocks of 1K is approx. 1.17TiB written.
//
// 39805M, 0.9999999900007903323961553855263092697380031246078278537831527269974242016478462970070809347116269575979...
// lower than 0.000000001 or 1 in 1.000.000.000 (1 billion)
// 39805M block of 1K is approx. 37.07TiB written.
//
// You will have to write 37TiB into one file to have a chance of 1 in a billion to have a duplicated nonce, you also
// have to consider it would compromise the first layer of AES256/GCM, there will be two more layers to break.
//
// see: `birthday.log.xz` for the dump of this program after running for about 50hs

func main() {
	const prec = 5000   // bits
	const bits = 12 * 8 // the first nonce for the first AES256
	const n = 1_000_000_000_000

	days := new(big.Float).SetPrec(prec).SetFloat64(math.Pow(2, bits))

	fmt.Printf("Precision: %v mantissa bits\n", prec)
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
}
