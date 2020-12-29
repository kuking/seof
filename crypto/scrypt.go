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

var CurrentSCryptParameters = SCryptParameters{ //>250ms
	N: 65536 * 2,
	R: 4 * 2,
	P: 1,
}

var MaxSCryptParameters = SCryptParameters{ //>4s
	N: 65536 * 8,
	R: 4 * 8,
	P: 1,
}

var MinSCryptParameters = SCryptParameters{ //21ms
	N: 65536 / 2,
	R: 4 / 2,
	P: 1,
}
