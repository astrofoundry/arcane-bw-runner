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

	if err := run(context.Background(), config, execCommandRunner{}, defaultRuntimePaths(), os.Geteuid()); err != nil {
		fmt.Fprintf(os.Stderr, "arcane-bw-runner: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("wrote .env.runtime")
}
