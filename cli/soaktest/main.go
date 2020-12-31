package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/kuking/seof"
	"os"
)

var password = "e924a81d0abd80b4c2ded664c7881a75575d9e45"

//var wholeSize = 1024 * 1024 * 1024
var wholeSize = 16 * 1024 * 1024
var seofBlockSize = 1024
var nat *os.File
var enc *seof.File

func main() {

	var err error
	b := make([]byte, 255)
	for i := 0; i < 0xff; i++ {
		b[i] = byte(i)
	}

	fmt.Println("seof soak test:")
	fmt.Printf("1. Creating 2 x %vMB files: native.soak, seof.soak\n", wholeSize/1024/1024)
	nat, err = os.Create("native.soak")
	assertErr(err)
	enc, err = seof.CreateExt("seof.soak", password, seofBlockSize, 5)
	assertErr(err)

	fmt.Printf("2. Writing %vMB of [0x00, 0x01, 0x02, ... 0xff] in: native.soak, seof.soak\n", wholeSize/1024/1024)
	blocks := wholeSize / len(b)
	for j := 0; j < blocks; j++ {
		n, err := nat.Write(b)
		assertWritten(n, len(b))
		assertErr(err)
		m, err := enc.Write(b)
		assertWritten(m, len(b))
		assertErr(err)
		if j%(blocks/50) == 0 {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
		}
	}
	fmt.Println(" done")

	for i, readBs := range []int{16, 256, seofBlockSize - 1, seofBlockSize, seofBlockSize + 1, seofBlockSize + 100, seofBlockSize * 2} {
		fmt.Printf("3.%v. Full compare files, read_block_size=%v\n", i+1, readBs)
		fullyCompare(readBs)
	}
}

func fullyCompare(readBlockSize int) {
	natb := make([]byte, readBlockSize)
	encb := make([]byte, readBlockSize)
	nat.Seek(0, 0)
	enc.Seek(0, 0)
	nn, mm := 0, 0
	for {
		n, err := nat.Read(natb)
		nn += n
		assertErr(err)
		m, err := enc.Read(encb)
		mm += m
		assertErr(err)
		if n != m {
			fmt.Printf("\nERROR: It did not read the same quantity of bytes, native=%v seof=%v\n", n, m)
			os.Exit(-1)
		}
		if !bytes.Equal(natb, encb) {
			fmt.Println("ERROR: Files are not equal.")
			fmt.Println("native:", hex.EncodeToString(natb))
			fmt.Println("  seof:", hex.EncodeToString(encb))
			os.Exit(-1)
		}
		if nn%(wholeSize/50) == 0 {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
		}
		if nn == wholeSize {
			fmt.Println("/done")
			break
		}
	}
}

func assertWritten(n, exp int) {
	if n != exp {
		fmt.Println("ERROR: expected to write", exp, "but wrote", n)
		os.Exit(-1)
	}
}

func assertErr(err error) {
	if err != nil {
		fmt.Println("ERROR:", err)
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
