package seof

import (
	"bytes"
	"encoding/hex"
	"fmt"
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
	assertNoErr(err, t)
	n, err := f.Write(data)
	assertNoErr(err, t)
	if n != len(data) {
		t.Fatal("did not write the whole buffer")
	}
	err = f.Close()
	assertNoErr(err, t)

	// open, read, close.
	f, err = OpenExt(tempFile.Name(), password, 1)
	assertNoErr(err, t)
	readBuf := make([]byte, BEBlockSize*5) // bigger, purposely
	n, err = f.Read(readBuf)
	if n != len(data) {
		t.Fatal("It did not read fully")
	}
	if !bytes.Equal(data, readBuf[0:n]) {
		t.Fatal("What was read was not correct what was initially written")
	}
	f.Close()
	assertNoErr(err, t)
}

// "trivial" test but necessary during the implementation, also maybe a good safety guard to leave around
func Test_NoPlainTextInDisk(t *testing.T) {
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

func Test_ChunkedBigWrite(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer os.Remove(tempFile.Name())
	data := crypto.RandBytes(256)

	// create, write, close.
	f, _ := CreateExt(tempFile.Name(), password, BEBlockSize, 1)

	for i := 0; i < 20; i++ {
		_, _ = f.Write(data)
	}
	_ = f.Close()

	// open, read, close.
	f, _ = OpenExt(tempFile.Name(), password, 1)
	readBuf := make([]byte, 256*20) // the whole thing should fit
	n, err := f.Read(readBuf)
	assertNoErr(err, t)
	if n != len(readBuf) {
		t.Fatal("It did not read fully")
	}
	for i := 0; i < 20; i++ {
		if !bytes.Equal(data, readBuf[i+256:(i+1)*256]) {
			fmt.Println("BLK:", i, "EXP:", hex.EncodeToString(data))
			fmt.Println("BLK:", i, "GOT:", hex.EncodeToString(readBuf[i+256:(i+1)*256]))
			t.Fatal("What was read was not correct what was initially written at chunk", i)
		}
	}
	f.Close()
	assertNoErr(err, t)
}

func Test_AnythingOnClosedFileFails(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer os.Remove(tempFile.Name())

	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 1)
	assertNoErr(err, t)

	err = f.Close()
	assertNoErr(err, t)

	_, err = f.WriteString("hola")
	if err != os.ErrClosed {
		t.Fatal()
	}

	_, err = f.Write([]byte{1, 2})
	if err != os.ErrClosed {
		t.Fatal()
	}
	_, err = f.WriteAt([]byte{1, 2}, 123)
	if err != os.ErrClosed {
		t.Fatal()
	}

	_, err = f.Read([]byte{1, 2})
	if err != os.ErrClosed {
		t.Fatal()
	}

	_, err = f.ReadAt([]byte{1, 2}, 123)
	if err != os.ErrClosed {
		t.Fatal()
	}

	_, err = f.Seek(0, 0)
	if err != os.ErrClosed {
		t.Fatal()
	}

	err = f.Close()
	if err != os.ErrClosed {
		t.Fatal()
	}

	err = f.Truncate(0)
	if err != os.ErrClosed {
		t.Fatal()
	}
}

func Test_ClosingAnErroredSoefIsOK(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer os.Remove(tempFile.Name())

	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 1)
	assertNoErr(err, t)
	for i := 0; i < 1024; i++ { // so it is bigger than 1 buffer
		f.WriteString("HELLO")
	}

	_ = f.file.Close() // this will trigger an error on the following read as the underlying file is close

	f.Seek(0, 0)
	b := make([]byte, 128)
	_, err = f.Read(b)
	if err.Error() != "could not read nonce bytes" {
		t.Fatal()
	}

	f.file, _ = os.Open(tempFile.Name()) // but won't trigger a second error on close. .. a bit hacky

	err = f.Close()
	assertNoErr(err, t)
}

func assertNoErr(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}
