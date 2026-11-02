// Command dhantra is the standalone remediation CLI. `plan` reads a
// contracts.RemediationRequest (JSON on stdin) and emits a
// contracts.RemediationPlan envelope.
//
// Status: scaffold. Planning + the authorization guard are real; isolated
// change execution lands in phase P3. The CLI never fabricates a change.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Armur-Ai/Dhantra/pkg/remediation"
	contracts "github.com/Armur-Ai/armur-contracts"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dhantra plan < request.json   |   dhantra version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "plan":
		runPlan()
	case "version":
		fmt.Printf("dhantra (scaffold) — contracts %s\n", contracts.SchemaVersion)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

func runPlan() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}
	var req contracts.RemediationRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		fmt.Fprintf(os.Stderr, "parse request: %v\n", err)
		os.Exit(1)
	}
	plan, err := remediation.Planner{}.Plan(context.Background(), req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plan refused: %v\n", err)
		os.Exit(1)
	}
	env, err := contracts.NewEnvelope(
		contracts.NSDhantra,
		contracts.Producer{Product: "dhantra", Version: "scaffold"},
		"RemediationPlan", plan,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}
