package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	os.Stdout.Write(run())
}

func run() []byte {
	filepath, mode, password := readConfig()
	data := readFile(filepath)
	switch mode {
	case "e":
		return Encrypt(data, password)
	case "d":
		return Decrypt(data, password)
	default:
		panic("unknown mode")
	}
}

func readConfig() (string, string, string) {
	if len(os.Args) != 4 {
		fmt.Println("password and mode are missing")
		os.Exit(1)
	}
	return os.Args[1], os.Args[2], os.Args[3]
}

func readFile(filepath string) []byte {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	return data
}
