// Command trivy-probe is a development-only SDK/sandbox feasibility binary.
// It accepts no image references, filesystem paths, or broker grants.
package main

import (
	"github.com/srelens/extension-trivy/internal/probe"
	"os"
)

func main() { os.Exit(probe.New().RunStdio()) }
