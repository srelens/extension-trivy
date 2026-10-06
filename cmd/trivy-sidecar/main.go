// Command trivy-sidecar serves JSON-RPC through the checked srelens SDK.
package main

import (
	"github.com/srelens/extension-trivy/internal/app"
	"os"
)

func main() { os.Exit(app.New().RunStdio()) }
