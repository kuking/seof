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
	defer deferredCleanup(tempFile)

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
		t.Fatal("read error, does not equals to initial write")
	}
	err = f.Close()
	assertNoErr(err, t)
}

// "trivial" test but necessary during the implementation, also maybe a good safety guard to leave around
func Test_NoPlainTextInDisk(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer deferredCleanup(tempFile)

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
	defer deferredCleanup(tempFile)

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
		if !bytes.Equal(data, readBuf[i*256:(i+1)*256]) {
			fmt.Println("BLK:", i, "EXP:", hex.EncodeToString(data))
			fmt.Println("BLK:", i, "GOT:", hex.EncodeToString(readBuf[i*256:(i+1)*256]))
			t.Fatal("What was read was not correct what was initially written at chunk", i)
		}
	}
	err = f.Close()
	assertNoErr(err, t)
}

func Test_AnythingOnClosedFileFails(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer deferredCleanup(tempFile)

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
	defer deferredCleanup(tempFile)

	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 1)
	assertNoErr(err, t)
	for i := 0; i < 1024; i++ { // so it is bigger than 1 buffer
		_, err = f.WriteString("HELLO")
		assertNoErr(err, t)
	}

	_ = f.file.Close() // this will trigger an error on the following read as the underlying file is close

	_, err = f.Seek(0, 0)
	assertNoErr(err, t)
	b := make([]byte, 128)
	_, err = f.Read(b)
	if err == nil {
		t.Fatal()
	}

	f.file, _ = os.Open(tempFile.Name()) // but won't trigger a second error on close. .. a bit hacky

	err = f.Close()
	assertNoErr(err, t)
}

func TestFile_Name(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer deferredCleanup(tempFile)
	f, _ := CreateExt(tempFile.Name(), password, BEBlockSize, 1)

	if f.Name() != tempFile.Name() {
		t.Fatal()
	}
	_ = f.Close()
}

func TestFile_Truncate(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer deferredCleanup(tempFile)

	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 10) // 10 is important to buffers are left in memory
	assertNoErr(err, t)
	for i := 0; i < 1024; i++ { // so it is bigger than 1 buffer
		_, err = f.WriteString("HELLO")
		assertNoErr(err, t)
	}

	// too far away
	err = f.Truncate(1024 * 1024)
	if err != os.ErrInvalid {
		t.Fatal()
	}

	// negative
	err = f.Truncate(-123)
	if err != os.ErrInvalid {
		t.Fatal()
	}

	// block aligned
	err = f.Truncate(BEBlockSize * 4)
	if err != nil {
		t.Fatal(err)
	}

	stats, err := tempFile.Stat()
	exp := int64(HeaderLength) + int64(5*f.blockZero.DiskBlockSize) // 4+1=5 because block-zero
	if stats.Size() != exp {
		t.Fatal("seems it did not truncate at the right place", stats.Size(), "!=", exp)
	}

	big := make([]byte, BEBlockSize*10)
	f.Seek(0, 0)
	n, err := f.Read(big)
	assertNoErr(err, t)
	if n != 4*BEBlockSize {
		t.Fatal()
	}

	// Cut half-way block
	newLength := BEBlockSize + BEBlockSize/2
	err = f.Truncate(int64(newLength))
	f.Seek(0, 0)
	n, err = f.Read(big)
	assertNoErr(err, t)
	if n != newLength {
		t.Fatal()
	}

	// for sure, after closing the file ... no buffers left hanging
	f.Close()
	stats, err = tempFile.Stat()
	if stats.Size() != int64(HeaderLength)+int64(3*f.blockZero.DiskBlockSize) { // +1 for blockzero
		t.Fatal("seems it did not truncate at the right place")
	}
}

func TestFile_Stat(t *testing.T) {
	tempFile, _ := ioutil.TempFile(os.TempDir(), "lala")
	defer deferredCleanup(tempFile)

	f, err := CreateExt(tempFile.Name(), password, BEBlockSize, 10) // 10 is important to buffers are left in memory
	assertNoErr(err, t)
	for i := 0; i < 1024; i++ { // so it is bigger than 1 buffer
		_, err = f.WriteString("HELLO")
		assertNoErr(err, t)
	}

	stats, err := f.Stat()
	assertNoErr(err, t)

	if stats.Size() != 1024*5 {
		t.Fatal("stats.size should return before encryption size")
	}

	if stats.Name() != f.Name() || stats.IsDir() {
		t.Fatal()
	}

	if stats.DiskBlockSize() != 1112 || stats.BEBlockSize() != 1024 || stats.BlocksWritten() != 2 || stats.EncryptedSize() != 240 {
		t.Fatal()
	}

	salt, n, r, p := stats.SCryptParameters()
	if len(salt) != 96 ||
		crypto.CurrentSCryptParameters.N != n ||
		crypto.CurrentSCryptParameters.P != p ||
		crypto.CurrentSCryptParameters.R != r {
		t.Fatal()
	}

	tempFileStats, err := tempFile.Stat()
	assertNoErr(err, t)

	// || tempFileStats.Sys() != stats.Sys() can't be compared
	if tempFileStats.Mode() != stats.Mode() || tempFileStats.ModTime() != stats.ModTime() {
		t.Fatal()
	}
}

func assertNoErr(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func deferredCleanup(file *os.File) {
	if file != nil {
		_ = os.Remove(file.Name())
	}
}
