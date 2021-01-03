package crypto

import (
	"golang.org/x/crypto/scrypt"
	"testing"
	"time"
)

func TestScryptParameters(t *testing.T) {
	keyLen := 32 * 3
	password := []byte("some password")
	salt := RandBytes(keyLen)
	start := time.Now()
	count := 2
	for i := 0; i < count; i++ {
		_, err := scrypt.Key(password, salt,
			int(RecommendedSCryptParameters.N), int(RecommendedSCryptParameters.R), int(RecommendedSCryptParameters.P), keyLen)
		if err != nil {
			t.Error(err)
		}
	}
	duration := time.Now().Sub(start)
	scryptMs := duration.Milliseconds() / int64(count)
	//fmt.Println("Scrypt parameters taking on average in this CPU:", scryptMs, "ms")
	if scryptMs < 600 {
		t.Errorf("Scrypt should take at least 600ms, it took %vms -- Time to increase its parameters", scryptMs)
	}
}
