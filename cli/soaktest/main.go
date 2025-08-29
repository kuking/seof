package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"runtime"

	"github.com/kuking/seof"
	"github.com/kuking/seof/crypto"
)

var password = "e924a81d0abd80b4c2ded664c7881a75575d9e45"

var wholeSize = 256 * 1024 * 1024
var seofBlockSize = 1024

var misalignedBlockSizes = []int{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	256,
	512,
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

	if len(os.Args) == 2 && os.Args[1] == "quick" {
		fmt.Println("\nNOTE: Running a quick test as per run parameters.")
		wholeSize = 1024 * 1024
	}
	fmt.Println()

	var err error
	fmt.Printf("1. Creating 2 x %vMB files: native.soak, seof.soak\n", wholeSize/1024/1024)
	nat, err = os.Create("native.soak")
	assertErr(err, "creating native.soak")
	enc, err = seof.CreateExt("seof.soak", []byte(password), crypto.RecommendedSCryptParameters, seofBlockSize, 5)
	assertErr(err, "creating seof.soak")

	fmt.Printf("2. Writing %vMB of [0x00, 0x01, 0x02, ... 0xff] in: native.soak, seof.soak\n", wholeSize/1024/1024)
	writeFullyUsingChunkSize(seofBlockSize)

	for i, bs := range misalignedBlockSizes {
		fmt.Printf("3.%v. Fully comparing files, using read_chunk_size=%v\n", i+1, bs)
		fullyCompare(bs)
	}

	for i, bs := range misalignedBlockSizes {
		fmt.Printf("4.%v.1. Rewriting wholy using chunk_size=%v\n", i+1, bs)
		writeFullyUsingChunkSize(bs)
		fmt.Printf("4.%v.2. Verifying (fast, using chunk_size=%v)\n", i+1, seofBlockSize)
		fullyCompare(seofBlockSize)
	}

	fmt.Printf("5.1. Writing %v random chunks of miscelaneous sizes of up to %v bytes\n", wholeSize/1024, seofBlockSize*2)
	writeRandomChunks(wholeSize/1024, seofBlockSize*2)
	fmt.Printf("5.2. Verifying (fast, using chunk_size=%v)\n", seofBlockSize)
	fullyCompare(seofBlockSize)

	fmt.Printf("6.1. Reading %v random chunks of miscelaneous sizes of up to %v bytes\n", wholeSize/1024, seofBlockSize*2)
	readingRandomChunks(wholeSize/1024, seofBlockSize*2)

	chunks := wholeSize / 1024 / 16
	threads := 64
	fmt.Printf("7.1 Synchronisation: reading native, writing encrypted %v chunks of up to %v bytes within %v concurrent threads\n", chunks*threads, seofBlockSize*2, threads)
	multithreadingWriteTest(chunks, seofBlockSize*2, threads)
	fmt.Printf("7.2. Verifying (fast, using chunk_size=%v)\n", seofBlockSize)
	fullyCompare(seofBlockSize)
	fmt.Printf("7.3. Synchronisation: reading %v encrypted chunks of up to %v bytes within %v concurrent threads\n", chunks*threads, seofBlockSize*2, threads)
	multithreadingReadTest(chunks, seofBlockSize*2, threads)

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
	for ofs < wholeSize {

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

func writeRandomChunks(chunks int, maxSize int) {
	lastDot := 0
	for chunk := 0; chunk < chunks; chunk++ {

		b := crypto.RandBytes(rand.Int() % maxSize)
		ofs := int64(rand.Int() % (wholeSize - len(b)))

		nOfs, err := nat.Seek(ofs, 0)
		assertErr(err, "seeking native file")
		if nOfs != ofs {
			fmt.Printf("ERROR: Couldn't seek to %v in native file.", ofs)
			os.Exit(-1)
		}

		n, err := nat.Write(b)
		assertWritten(n, len(b))
		assertErr(err, "writing native file")

		mOfs, err := enc.Seek(ofs, 0)
		assertErr(err, "seeking encrypted file")
		if mOfs != ofs {
			fmt.Printf("ERROR: Couldn't seek to %v in encrypted file.", ofs)
			os.Exit(-1)
		}

		m, err := enc.Write(b)
		assertWritten(m, len(b))
		assertErr(err, "writing encrypted file")
		if n != m || n != len(b) || m != len(b) {
			fmt.Printf(
				"\nERROR: It did not write the expected quantity, written native=%v, seof=%v, expected=%v, ofs=%v\n",
				n, m, len(b), ofs)
			os.Exit(-1)
		}

		if lastDot < chunk/(chunks/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = chunk / (chunks / 50)
		}
	}
	fmt.Println(" done")
}

func readingRandomChunks(chunks int, maxSize int) {
	lastDot := 0
	for chunk := 0; chunk < chunks; chunk++ {

		size := rand.Int() % maxSize
		nb := make([]byte, size)
		mb := make([]byte, size)
		ofs := int64(rand.Int() % (wholeSize - len(nb)))

		n, err := nat.ReadAt(nb, ofs)
		assertErr(err, "reading native file")

		m, err := enc.ReadAt(mb, ofs)
		assertErr(err, "reading encrypted file")
		if n != m || n != len(nb) || m != len(mb) {
			fmt.Printf(
				"\nERROR: It did not read the expected quantity, read native=%v, seof=%v, expected=%v, ofs=%v\n",
				n, m, len(nb), ofs)
			os.Exit(-1)
		}

		if !bytes.Equal(nb, mb) {
			fmt.Println("ERROR: Files are not equal.")
			fmt.Println("native:", hex.EncodeToString(nb))
			fmt.Println("  seof:", hex.EncodeToString(mb))
			os.Exit(-1)
		}

		if lastDot < chunk/(chunks/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = chunk / (chunks / 50)
		}
	}
	fmt.Println(" done")
}

func multithreadingWriteTest(chunks int, maxSize int, threads int) {
	runtime.GOMAXPROCS(threads * 2)
	chunkRead := make(chan int, 5)
	for t := 0; t < threads; t++ {
		go concurrentReadWriter(chunkRead, chunks, maxSize, t)
	}

	lastDot := 0
	for t := 0; t < threads*chunks; t++ {
		<-chunkRead
		if lastDot < t/(threads*chunks/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = t / (threads * chunks / 50)
		}
	}
	fmt.Println(" done")
}

func concurrentReadWriter(chunkRead chan int, chunks int, maxSize int, threadNo int) {
	for chunk := 0; chunk < chunks; chunk++ {
		size := rand.Int() % maxSize
		nb := make([]byte, size)
		ofs := int64(rand.Int() % (wholeSize - len(nb)))

		n, err := nat.ReadAt(nb, ofs)
		assertErr(err, "reading native file")

		m, err := enc.WriteAt(nb, ofs)
		assertErr(err, "writing encrypted file")
		if n != m || n != len(nb) {
			fmt.Printf(
				"\nERROR: It did not read/write the expected quantity, read native=%v, write seof=%v, expected=%v, ofs=%v (thread no %v)\n",
				n, m, len(nb), ofs, threadNo)
			os.Exit(-1)
		}
		chunkRead <- threadNo
	}
}

func multithreadingReadTest(chunks int, maxSize int, threads int) {
	runtime.GOMAXPROCS(threads * 2)
	chunkRead := make(chan int, 5)
	for t := 0; t < threads; t++ {
		go concurrentRead(chunkRead, chunks, maxSize, t)
	}

	lastDot := 0
	for t := 0; t < threads*chunks; t++ {
		<-chunkRead
		if lastDot < t/(threads*chunks/50) {
			_, _ = os.Stdout.WriteString(".")
			_ = os.Stdout.Sync()
			lastDot = t / (threads * chunks / 50)
		}
	}
	fmt.Println(" done")
}

func concurrentRead(chunkRead chan int, chunks int, maxSize int, threadNo int) {
	for chunk := 0; chunk < chunks; chunk++ {
		size := rand.Int() % maxSize
		nb := make([]byte, size)
		mb := make([]byte, size)
		ofs := int64(rand.Int() % (wholeSize - len(nb)))

		n, err := nat.ReadAt(nb, ofs)
		assertErr(err, "reading native file")

		m, err := enc.ReadAt(mb, ofs)
		assertErr(err, "reading encrypted file")
		if n != m || n != len(nb) || m != len(mb) {
			fmt.Printf(
				"\nERROR: It did not read the expected quantity, read native=%v, read seof=%v, expected=%v, ofs=%v (thread no %v)\n",
				n, m, len(nb), ofs, threadNo)
			os.Exit(-1)
		}
		if !bytes.Equal(nb, mb) {
			fmt.Println("ERROR: Files are not equal.")
			fmt.Println("native:", hex.EncodeToString(nb))
			fmt.Println("  seof:", hex.EncodeToString(mb))
			os.Exit(-1)
		}

		chunkRead <- threadNo
	}
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
		_ = os.Remove(nat.Name())

		err = enc.Close()
		if err != nil {
			fmt.Println(err)
		}
		_ = os.Remove(enc.Name())

		os.Exit(-1)
	}
}
