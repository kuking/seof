package seof

import (
	"bytes"
	"github.com/kuking/seof/crypto"
	"io/ioutil"
	"os"
	"testing"
)

func Test_HappySequentialWriteRead(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer os.Remove(tempFile.Name())
	data := crypto.RandBytes(BEBlockSize*3 + BEBlockSize/3)

	// create, write, close.
	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 1)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.Write(data)
	if n != len(data) {
		t.Fatal("did not write the whole buffer")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}

	// open, read, close.
	f, err = OpenExt(tempFile.Name(), password, 1)
	if err != nil {
		t.Fatal(err)
	}
	readBuf := make([]byte, BEBlockSize*5) // bigger, purposely
	n, err = f.Read(readBuf)
	if n != len(data) {
		t.Fatal("It did not read fully")
	}
	if !bytes.Equal(data, readBuf[:n]) {
		t.Fatal("What was read was not correct what was initially written")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func Test_NoPlainTextInDisk(t *testing.T) {
	// "trivial" test but necessary during the implementation, also maybe a good safety guard to leave around
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer os.Remove(tempFile.Name())

	data := crypto.RandBytes(128)
	f, _ := CreateExt(tempFile.Name(), password, BEBlockSize, 1)
	for i := 0; i < 100; i++ {
		_, _ = f.Write(data)
	}
	_ = f.Close()

	rf, _ := os.Open(tempFile.Name())
	raw, _ := ioutil.ReadAll(rf)
	if bytes.Contains(raw, data) {
		t.Fatal("encryption might not be working")
	}
}
