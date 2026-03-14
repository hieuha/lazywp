package main

import (
	"os"

	"github.com/hieuha/lazywp/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
