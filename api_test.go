package seof

import (
	"os"
	"testing"

	"github.com/kuking/seof/crypto"
)

const (
	password    = "4f760f9e67c61ff63044fa97e0b00fdc96c744a3"
	BEBlockSize = 1024
)

func TestNoUsableMethods(t *testing.T) {
	if _, err := Create("any"); err == nil {
		t.Fatal("Create should not work, use CreateExt")
	}
	if _, err := Open("any"); err == nil {
		t.Fatal("Open should not work, use OpenExt")
	}
	if _, err := OpenFile("any", 0, os.ModeAppend); err == nil {
		t.Fatal("OpenFile should not work, use OpenExt")
	}
}

func TestCreateExt_InvalidArguments(t *testing.T) {
	for _, password := range []string{"", "1234567890", "12345678901"} {
		if _, err := CreateExt("file", []byte(password), crypto.MinSCryptParameters, BEBlockSize, 1); err == nil {
			t.Fatal("password should be at least 12 characters long")
		}
	}
	for _, blockSize := range []int{-123, -1, 0, 10, 1023, 128*1024 + 1, 256 * 1024} {
		if _, err := CreateExt("file", []byte(password), crypto.MinSCryptParameters, blockSize, 1); err == nil {
			t.Fatal("block size should be: 1kb<=block_size<128kb")
		}
	}
	for _, memBuffers := range []int{-123, -1, 0, 129, 65535} {
		if _, err := CreateExt("file", []byte(password), crypto.MinSCryptParameters, BEBlockSize, memBuffers); err == nil {
			t.Fatal("memory buffers be: 1<=buffers<128")
		}
	}
	_, err := CreateExt("", []byte(password), crypto.MinSCryptParameters, BEBlockSize, 1)
	if err == nil {
		t.Fatal("invalid filename should fail")
	}
}

func TestOpenExt_InvalidArguments(t *testing.T) {
	for _, buffers := range []int{-123, -1, 0, 1025, 128 * 1024} {
		_, err := OpenExt("file", []byte(password), buffers)
		if err == nil {
			t.Fatal("memory buffers should be checked for bounds")
		}
	}
	_, err := OpenExt("", []byte(password), 1)
	if err == nil {
		t.Fatal("invalid filename should fail")
	}
}
