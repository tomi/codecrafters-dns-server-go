package main

import (
	"flag"
)

func tryParseResolverArg() (bool, string) {
	var resolverAddress string
	flag.StringVar(&resolverAddress, "resolver", "", "Address of the resolver")
	flag.Parse()

	// Check if the resolver flag is provided
	if resolverAddress == "" {
		return false, ""
	}

	return true, resolverAddress
}
