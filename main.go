package main

import (
	"os"

	"github.com/rybo/secretstash/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
