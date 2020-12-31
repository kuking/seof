package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/kuking/seof"
	"github.com/kuking/seof/crypto"
	"os"
)

var password = "e924a81d0abd80b4c2ded664c7881a75575d9e45"

//var wholeSize = 1024 * 1024 * 1024
var wholeSize = 16 * 1024 * 1024
var seofBlockSize = 1024

var misalignedBlockSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	256,
	seofBlockSize - 100,
	seofBlockSize - 1,
	seofBlockSize,
	seofBlockSize + 1,
	seofBlockSize + 100,
	seofBlockSize * 2,
	seofBlockSize * 3,
	seofBlockSize * 4,
	(seofBlockSize * 4) - 1,
	(seofBlockSize * 4) + 1}

var nat *os.File
var enc *seof.File

func main() {

	fmt.Println(`soaktest: seof soak test, creates a native file and a seof encrypted file.
  applies many different IO operations equally to both files and verifies both behave similar. You want a fast disk (NVMe).`)
	fmt.Println()

	var err error
	fmt.Printf("1. Creating 2 x %vMB files: native.soak, seof.soak\n", wholeSize/1024/1024)
	nat, err = os.Create("native.soak")
	assertErr(err, "creating native.soak")
	enc, err = seof.CreateExt("seof.soak", password, seofBlockSize, 5)
	assertErr(err, "creating seof.soak")

	fmt.Printf("2. Writing %vMB of [0x00, 0x01, 0x02, ... 0xff] in: native.soak, seof.soak\n", wholeSize/1024/1024)
	writeFullyUsingChunkSize(seofBlockSize)

	for i, bs := range misalignedBlockSizes {
		fmt.Printf("3.%v. Fully comparing files, using read_chunk_size=%v\n", i+1, bs)
		fullyCompare(bs)
	}

	for i, bs := range misalignedBlockSizes {
		fmt.Printf("4.%v.1. Rewriting using chunk_size=%v\n", i+1, bs)
		writeFullyUsingChunkSize(bs)
		fmt.Printf("4.%v.2. Verifying (fast, using chunk_size=%v)\n", i+1, seofBlockSize)
		fullyCompare(seofBlockSize)
	}

	fmt.Println("\nSUCCESS!")
	_ = nat.Close()
	_ = os.Remove(nat.Name())
	_ = enc.Close()
	_ = os.Remove(enc.Name())
}

func fullyCompare(readChunkSize int) {
	natb := make([]byte, readChunkSize)
	encb := make([]byte, readChunkSize)
	_, _ = nat.Seek(0, 0)
	_, _ = enc.Seek(0, 0)
	lastDot := 0
	ofs := 0
	for {
		//if ofs == 16777068 {
		//	fmt.Println("debugging")
		//}
		n, err := nat.Read(natb)
		if err != nil {
			fmt.Println("nat", ofs, n, wholeSize)
		}
		assertErr(err, "reading native file")
		m, err := enc.Read(encb)
		if err != nil {
			fmt.Println("enc", ofs, m, wholeSize)
		}
		assertErr(err, "reading encrypted file")
		if n != m {
			fmt.Printf("\nERROR: It did not read the same quantity of bytes, native=%v seof=%v, ofs=%v\n", n, m, ofs)
			os.Exit(-1)
		}
		ofs += n
		if !bytes.Equal(natb, encb) {
			fmt.Println("ERROR: Files are not equal.")
			fmt.Println("native:", hex.EncodeToString(natb))
			fmt.Println("  seof:", hex.EncodeToString(encb))
			os.Exit(-1)
		}
		if lastDot < ofs/(wholeSize/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = ofs / (wholeSize / 50)
		}
		if ofs == wholeSize {
			fmt.Println(" done")
			break
		}
	}
}

func writeFullyUsingChunkSize(cs int) {
	_, _ = nat.Seek(0, 0)
	_, _ = enc.Seek(0, 0)
	lastDot := 0
	ofs := 0
	for ; ofs < wholeSize; {

		toWrite := cs
		if ofs+cs > wholeSize {
			toWrite = wholeSize - ofs
		}
		b := crypto.RandBytes(toWrite)
		n, err := nat.Write(b)
		assertWritten(n, toWrite)
		assertErr(err, "writing native file")
		m, err := enc.Write(b)
		assertWritten(m, toWrite)
		assertErr(err, "writing encrypted file")
		if n != m || n != toWrite || m != toWrite {
			fmt.Printf(
				"\nERROR: It did not write the expected quantity, written native=%v, seof=%v, expected=%v, ofs=%v\n",
				n, m, toWrite, ofs)
			os.Exit(-1)
		}
		ofs += toWrite

		if lastDot < ofs/(wholeSize/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = ofs / (wholeSize / 50)
		}
	}
	fmt.Println(" done")
}

func assertWritten(n, exp int) {
	if n != exp {
		fmt.Println("\nERROR: expected to write", exp, "but wrote", n)
		os.Exit(-1)
	}
}

func assertErr(err error, desc string) {
	if err != nil {
		fmt.Println("\nERROR:", desc, "err:", err)
		err = nat.Close()
		if err != nil {
			fmt.Println(err)
		}
		os.Remove(nat.Name())

		err = enc.Close()
		if err != nil {
			fmt.Println(err)
		}
		os.Remove(enc.Name())

		os.Exit(-1)
	}
}
