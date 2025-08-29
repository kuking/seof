package seof

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kuking/seof/crypto"
)

func TestHeaderStruct(t *testing.T) {
	h := Header{
		Magic:         0xdeadbeef,
		ScriptSalt:    [96]byte{},
		ScriptN:       crypto.RecommendedSCryptParameters.N,
		ScriptR:       crypto.RecommendedSCryptParameters.R,
		ScriptP:       crypto.RecommendedSCryptParameters.P,
		DiskBlockSize: 1024,
		TailOfZeros:   [8]byte{},
	}

	buf := make([]byte, 0, 1024)
	p := bytes.NewBuffer(buf)
	if binary.Write(p, binary.LittleEndian, &h) != nil {
		t.Fatal()
	}
	if p.Len() != 128 || p.Len() != HeaderLength {
		t.Fatal("header should be 128 bytes")
	}
}

func TestHeader_Verify(t *testing.T) {
	h := givenValidHeader()
	err := h.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

func TestHeader_WrongMagic(t *testing.T) {
	h := givenValidHeader()
	h.Magic = 123
	if h.Verify() == nil {
		t.Fatal("header should not be valid with that magic")
	}
}

func TestHeader_ZeroSalt(t *testing.T) {
	h := givenValidHeader()
	for i := 0; i < len(h.ScriptSalt); i++ {
		h.ScriptSalt[i] = 0
	}
	if h.Verify() == nil {
		t.Fatal("A header with an 'empty' (zeroed) salt is wrong")
	}
}

func TestHeader_ScriptParams(t *testing.T) {
	h := givenValidHeader()
	// N
	h.ScriptN = crypto.MinSCryptParameters.N - 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptN = crypto.MaxSCryptParameters.N + 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptN = crypto.MaxSCryptParameters.N

	// N
	h.ScriptP = crypto.MinSCryptParameters.P - 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptP = crypto.MaxSCryptParameters.P + 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptP = crypto.MaxSCryptParameters.P

	// N
	h.ScriptR = crypto.MinSCryptParameters.R - 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptR = crypto.MaxSCryptParameters.R + 1
	if h.Verify() == nil {
		t.Fatal()
	}
	h.ScriptR = crypto.MaxSCryptParameters.R
}

func TestHeader_DiskBlockSize(t *testing.T) {
	h := givenValidHeader()
	h.DiskBlockSize = 1111
	if h.Verify() == nil {
		t.Fatal("disk block size should be at least 1500 bytes")
	}
	h.DiskBlockSize = 196608 + 1
	if h.Verify() == nil {
		t.Fatal("disk block size should be smaller than 196608 bytes")
	}
}

func TestHeader_TailOfZeros(t *testing.T) {
	h := givenValidHeader()
	h.TailOfZeros[7] = 1
	if h.Verify() == nil {
		t.Fatal("tailOfZeros should be all zeroes")
	}
}

func TestBlockZero_Serialising(t *testing.T) {
	bz := BlockZero{
		BEncBlockSize: 1,
		DiskBlockSize: 2,
		BEncFileSize:  3,
		BlocksWritten: 4,
	}
	bz2, err := BlockZeroFromBytes(bz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if bz2 == nil {
		t.Fatal()
	}
	if bz != *bz2 {
		t.Fatal()
	}
	if len(bz.Bytes()) != 4+4+8+8 {
		t.Fatal()
	}

}

func givenValidHeader() Header {
	h := Header{
		Magic:         HeaderMagic,
		ScriptSalt:    [96]byte{},
		ScriptN:       crypto.RecommendedSCryptParameters.N,
		ScriptR:       crypto.RecommendedSCryptParameters.R,
		ScriptP:       crypto.RecommendedSCryptParameters.P,
		DiskBlockSize: 1524,
		TailOfZeros:   [8]byte{},
	}
	copy(h.ScriptSalt[:], crypto.RandBytes(96))
	return h
}
