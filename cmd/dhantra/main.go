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
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Armur-Ai/Dhantra/pkg/remediation"
	contracts "github.com/Armur-Ai/armur-contracts"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dhantra plan < request.json   |   dhantra from-snapshot < snapshot.json   |   dhantra dryrun --propose <dir> < plan.json   |   dhantra version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "plan":
		runPlan()
	case "from-snapshot":
		runFromSnapshot()
	case "dryrun":
		runDryRun(os.Args[2:])
	case "version":
		fmt.Printf("dhantra (scaffold) — contracts %s\n", contracts.SchemaVersion)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

// runDryRun reads a RemediationPlan (stdin) and proposes the files under
// --propose, emitting a ChangeArtifact envelope. Nothing is applied — the
// artifact is marked review_state="proposed".
func runDryRun(args []string) {
	fs := flag.NewFlagSet("dryrun", flag.ExitOnError)
	proposeDir := fs.String("propose", "", "directory of proposed file contents (required)")
	_ = fs.Parse(args)
	if *proposeDir == "" {
		fmt.Fprintln(os.Stderr, "dhantra dryrun: --propose <dir> is required")
		os.Exit(2)
	}
	raw, _ := io.ReadAll(os.Stdin)
	var plan contracts.RemediationPlan
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &plan); err != nil {
			fmt.Fprintf(os.Stderr, "parse plan: %v\n", err)
			os.Exit(1)
		}
	}
	proposed, err := readProposed(*proposeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read proposed: %v\n", err)
		os.Exit(1)
	}
	art, err := remediation.Planner{}.DryRun(plan, proposed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dryrun: %v\n", err)
		os.Exit(1)
	}
	env, err := contracts.NewEnvelope(
		contracts.NSDhantra,
		contracts.Producer{Product: "dhantra", Version: "scaffold"},
		"ChangeArtifact", art,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}

// readProposed loads a directory tree into a map of repo-relative path -> bytes.
func readProposed(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out, err
}

// runFromSnapshot reads a Pentest Swarm AssessmentSnapshot envelope (JSON on
// stdin) and emits a RemediationRequest envelope derived from its verified
// weaknesses — ready to pipe into `dhantra plan`.
func runFromSnapshot() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}
	var env contracts.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fmt.Fprintf(os.Stderr, "parse envelope: %v\n", err)
		os.Exit(1)
	}
	if _, err := contracts.CheckEnvelope(env); err != nil {
		fmt.Fprintf(os.Stderr, "from-snapshot: incompatible envelope: %v\n", err)
		os.Exit(1)
	}
	if env.Kind != "AssessmentSnapshot" {
		fmt.Fprintf(os.Stderr, "from-snapshot: expected an AssessmentSnapshot envelope, got %q\n", env.Kind)
		os.Exit(1)
	}
	var snap contracts.AssessmentSnapshot
	if err := env.Decode(&snap); err != nil {
		fmt.Fprintf(os.Stderr, "decode snapshot: %v\n", err)
		os.Exit(1)
	}
	req := remediation.RequestFromSnapshot(snap)
	out, err := contracts.NewEnvelope(
		contracts.NSDhantra,
		contracts.Producer{Product: "dhantra", Version: "scaffold"},
		"RemediationRequest", req,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
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
