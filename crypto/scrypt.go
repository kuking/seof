package crypto

// Script parameters configuration valid at Dec 2020 for an AMD Ryzen 7 3800X 8-Core Processor
//
// Minimum accepted: a key spec with lower parameters shall not be accepted; processing in less than 21ms
// Currently recommended: parameters targeting at least 250ms for deriving a key
// Maximum accepted: an upper limit defined to avoid potential DoS attacks; maximum set at 4s

type SCryptParameters struct {
	N uint32
	R uint32
	P uint32
}

var CurrentSCryptParameters = SCryptParameters{ //>300ms
	N: 1 << 16,
	R: 1 << 4,
	P: 1 << 0,
}

var MaxSCryptParameters = SCryptParameters{ //>9s
	N: 1 << 19,
	R: 1 << 6,
	P: 1 << 0,
}

var MinSCryptParameters = SCryptParameters{ //21ms
	N: 1 << 14,
	R: 1 << 2,
	P: 1 << 0,
}
