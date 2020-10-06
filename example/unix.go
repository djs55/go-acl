// Copyright (c) 2015 Joseph Naegele. See LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/naegelejd/go-acl"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatal("Missing filename")
	}
	filename := flag.Arg(0)

	getAccess(filename)
	getExtended(filename)
}

func getAccess(filename string) {
	a, err := acl.GetFileAccess(filename)
	if err != nil {
		log.Printf("Failed to get ACL from %s (%s)", filename, err)
		return
	}
	defer a.Free()
	fmt.Print("ACL repr:\n", a)
}

func getExtended(filename string) {
	a, err := acl.GetFileExtended(filename)
	if err != nil {
		log.Printf("Failed to get extended ACL from %s (%s)", filename, err)
		return
	}
	defer a.Free()
	fmt.Print("ACL repr:\n", a)
}
