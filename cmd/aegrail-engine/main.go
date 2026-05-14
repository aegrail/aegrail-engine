// Command aegrail-engine is the Kubernetes-deployable enforcement
// engine for aegrail. It runs as a sidecar alongside an AI-agent
// container, intercepts the agent's outbound HTTP traffic via an
// HTTP forward proxy, applies an allowlist policy, and writes a
// SHA-256-chained audit log compatible with the aegrail Python
// library's format.
//
// This file is a placeholder. The v0.1.0 milestone replaces it
// with the real proxy implementation.
package main

import (
	"fmt"
	"os"
)

// Version is overwritten at build time via -ldflags.
var Version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(Version)
		return
	}
	fmt.Fprintln(os.Stderr, "aegrail-engine: pre-release placeholder.")
	fmt.Fprintln(os.Stderr, "v0.1.0 ships the HTTP forward proxy + Helm chart.")
	fmt.Fprintln(os.Stderr, "See: https://github.com/arpitcoder/aegrail-engine#roadmap")
	os.Exit(0)
}
