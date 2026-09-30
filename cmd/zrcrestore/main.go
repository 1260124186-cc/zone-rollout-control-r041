// Command zrcrestore is the offline snapshot restore tool. It never opens a
// network socket and never talks to a running zrc process: it only reads a
// candidate snapshot file and, after validation and explicit confirmation,
// atomically replaces the target snapshot file. Run with -h for usage.
package main

import (
	"fmt"
	"os"

	"solo-0014-zone-rollout-control/internal/restore"
)

func main() {
	if err := restore.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "zrcrestore:", err)
		os.Exit(1)
	}
}
