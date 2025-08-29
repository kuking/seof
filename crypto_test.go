package seof

import (
	"testing"

	"github.com/kuking/seof/crypto"
)

func TestSealOpen(t *testing.T) {
	f := File{}
	h := givenValidHeader()
	_ = f.initialiseCiphers([]byte(password), &h)

	plainText := "This is a secret"
	cipherText, nonce := f.seal([]byte(plainText), 1234)
	recoveredText, err := f.unseal(cipherText, 1234, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if string(recoveredText) != plainText {
		t.Fatal("recovered plaintext not equal")
	}
}

func TestSealOpen_InvalidBlockNo(t *testing.T) {
	f := File{}
	h := givenValidHeader()
	_ = f.initialiseCiphers([]byte(password), &h)
	plainText := "This is a secret"
	cipherText, nonce := f.seal([]byte(plainText), 1234)
	_, err := f.unseal(cipherText, 5432, nonce)
	if err == nil {
		t.Fatal(err)
	}
}

func TestSealOpen_Sizes(t *testing.T) {
	f := File{}
	h := givenValidHeader()
	_ = f.initialiseCiphers([]byte(password), &h)
	plainText := "This is a secret"
	cipherText, nonce := f.seal([]byte(plainText), 1234)

	if len(nonce) != 36 || len(nonce) != nonceSize {
		t.Fatal("nonce has to be 12*3 bytes")
	}
	if float32(len(plainText))*1.5 > float32(len(cipherText)) {
		t.Fatal("cipherText seems too short")
	}
}

// of course we don't intend to test the crypto primitives here, we want to assert without any doubt we did not "f.up"
// the integration with the crypto primitives, now or in the future.
func TestSealOpen_AnyByteChangeShouldFail(t *testing.T) {
	f := File{}
	h := givenValidHeader()
	_ = f.initialiseCiphers([]byte(password), &h)
	plainText := "This is a secret"
	cipherText, nonce := f.seal([]byte(plainText), 1234)
	// cipher-text
	for i := 0; i < len(cipherText); i++ {
		orig := cipherText[i]
		cipherText[i] = crypto.RandBytes(1)[0]
		if cipherText[i] == orig {
			cipherText[i]++
		}
		_, err := f.unseal(cipherText, 1234, nonce)
		if err == nil {
			t.Fatal("this should have failed after changing one byte in the cipherText")
		}
		cipherText[i] = orig
	}
	// nonce
	for i := 0; i < len(nonce); i++ {
		orig := nonce[i]
		nonce[i] = orig ^ crypto.RandBytes(1)[0]
		if nonce[i] == orig {
			nonce[i]++
		}
		_, err := f.unseal(cipherText, 1234, nonce)
		if err == nil {
			t.Fatal("this should have failed after changing one byte in the cipherText")
		}
		nonce[i] = orig
	}
}
