package main

import (
	"fmt"
	"os"

	"github.com/dolmen-go/cidr2hcmask"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println("usage:", os.Args[0], "<ip/bits>")
		os.Exit(1)
	}
	net, err := cidr2hcmask.ParseCIDR(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cidr2hcmask.CIDR2HCMaskWrite(net, os.Stdout)
}
