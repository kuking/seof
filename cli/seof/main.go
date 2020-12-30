package main

import (
	"fmt"
	"github.com/kuking/seof"
	"io"
	"os"
)

func main() {

	if len(os.Args) == 0 || os.Args[1] == "enc" {
		file, err := seof.CreateExt("file.seof", "a very long password don't tell anybody", 1024, 5)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		n, err := io.Copy(file, os.Stdin)
		fmt.Println(n, "bytes written. err:", err)
	} else if os.Args[1] == "dec" {
		file, err := seof.OpenExt("file.seof", "a very long password don't tell anybody", 5)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		_, err = io.Copy(os.Stdout, file)
		if err != nil {
			panic(err)
		}
	}

}
