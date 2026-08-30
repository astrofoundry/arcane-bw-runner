package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

func main() {
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		if !errors.Is(err, errHelpRequested) {
			fmt.Fprintf(os.Stderr, "arcane-bw-runner: %v\n", err)
		}
		os.Exit(2)
	}

	paths := defaultRuntimePaths()
	paths.output = config.output
	if err := run(context.Background(), config, execCommandRunner{}, paths, os.Geteuid()); err != nil {
		fmt.Fprintf(os.Stderr, "arcane-bw-runner: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s\n", config.output)
}
