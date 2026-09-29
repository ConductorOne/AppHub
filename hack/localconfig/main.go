// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command localconfig writes the gitignored loopback serve skeleton.
//
// Usage:
//
//	go run ./hack/localconfig -dir .local -static-dir frontend/dist
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/conductorone/apphub/internal/serverconfig"
)

func main() {
	dir := flag.String("dir", "", "directory for the local serve skeleton")
	staticDir := flag.String("static-dir", "", "absolute or relative portal static directory")
	endpoint := flag.String("endpoint", "http://127.0.0.1:18000", "local DynamoDB endpoint")
	region := flag.String("region", "us-east-1", "local DynamoDB region")
	table := flag.String("table", "apphub-local", "local DynamoDB table")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "localconfig: unexpected arguments")
		os.Exit(2)
	}

	result, err := serverconfig.WriteLocal(serverconfig.LocalOptions{
		Dir: *dir, StaticDir: *staticDir, Endpoint: *endpoint, Region: *region, TableName: *table,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "localconfig: %v\n", err)
		os.Exit(1)
	}
	for _, path := range result.Created {
		fmt.Printf("wrote %s\n", path)
	}
	for _, path := range result.Existing {
		fmt.Printf("kept %s\n", path)
	}
	fmt.Printf("Replace the Google client id and %s/client.secret, then:\n", result.Dir)
	fmt.Printf("  make infra-up\n  make dev APPHUB_CONFIG=%s\n", result.Config)
}
