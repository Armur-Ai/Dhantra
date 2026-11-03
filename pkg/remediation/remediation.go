// Package remediation is Dhantra's remediation engine: it turns an authorized
// contracts.RemediationRequest into a contracts.RemediationPlan, and (later)
// executes the plan in an isolated workspace to produce a contracts.ChangeArtifact,
// then orchestrates verification. It is NOT a SOC.
//
// Status: scaffold. Planning + the authorization guard are real and tested;
// isolated change execution and verification orchestration land in phase P3.
// A change is never proof of repair — outputs keep source/build/deploy/runtime
// verification separate (see contracts.VerificationRun), and nothing is applied
// without an in-scope, allowed change class.
package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// Planner produces a RemediationPlan for an authorized request.
type Planner struct{}

// Plan validates authorization and drafts a plan. It refuses when the request
// carries no allowed change classes — a CVSS score is not authorization, and an
// unscoped request blocks the affected change (not unrelated read-only work).
func (Planner) Plan(_ context.Context, req contracts.RemediationRequest) (contracts.RemediationPlan, error) {
	if len(req.AllowedChanges) == 0 {
		return contracts.RemediationPlan{}, fmt.Errorf("remediation: request %q has no allowed change classes — refusing to plan a change", req.RequestID)
	}
	if req.RequestID == "" {
		return contracts.RemediationPlan{}, fmt.Errorf("remediation: request id required")
	}
	return contracts.RemediationPlan{
		PlanID:        fmt.Sprintf("plan-%d", time.Now().UnixNano()),
		RequestRef:    req.RequestID,
		Strategy:      "root_cause", // proposed; refined during execution
		BaseRevisions: []string{req.Source.CommitID},
		RequiredTests: req.RequestedVerification,
		Assumptions:   []string{"scaffold: change execution not yet implemented (P3)"},
		MissingInputs: missingInputs(req),
	}, nil
}

func missingInputs(req contracts.RemediationRequest) []string {
	var m []string
	if req.Source.CommitID == "" {
		m = append(m, "source commit id")
	}
	if len(req.FindingRefs) == 0 {
		m = append(m, "finding refs")
	}
	return m
}

// PrepareWorkspace creates an isolated workspace pinned to the plan's base
// revision, ready for change execution. The caller must defer Cleanup. This is
// the honest seam between planning and execution: it sets up the sandbox but
// makes no changes.
func (Planner) PrepareWorkspace(plan contracts.RemediationPlan) (*Workspace, error) {
	base := ""
	if len(plan.BaseRevisions) > 0 {
		base = plan.BaseRevisions[0]
	}
	return NewWorkspace(base)
}

// DryRun writes the proposed file contents into a fresh isolated workspace and
// returns a ChangeArtifact describing them — with a real content digest — but
// WITHOUT applying anything to any real repository. The artifact is explicitly
// marked review_state="proposed": a dry run is a proposal, never a repair.
func (Planner) DryRun(plan contracts.RemediationPlan, proposed map[string][]byte) (contracts.ChangeArtifact, error) {
	ws, err := (Planner{}).PrepareWorkspace(plan)
	if err != nil {
		return contracts.ChangeArtifact{}, err
	}
	defer ws.Cleanup()

	paths := make([]string, 0, len(proposed))
	for p := range proposed {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic digest + changed-path ordering

	h := sha256.New()
	for _, p := range paths {
		if err := ws.WriteFile(p, proposed[p]); err != nil {
			return contracts.ChangeArtifact{}, err
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(proposed[p])
	}
	base := ""
	if len(plan.BaseRevisions) > 0 {
		base = plan.BaseRevisions[0]
	}
	return contracts.ChangeArtifact{
		ChangeID:         "dryrun-" + hex.EncodeToString(h.Sum(nil))[:12],
		BaseRevision:     base,
		PatchDigest:      hex.EncodeToString(h.Sum(nil)),
		ChangedPaths:     paths,
		AgentAttribution: "dhantra (automated dry-run)",
		ReviewState:      "proposed", // nothing applied; a proposal only
	}, nil
}

// Execute would apply the plan in an isolated workspace and return a
// ChangeArtifact. Not implemented in the scaffold: it returns an explicit error
// rather than fabricating a change (never claim a repair that did not happen).
func (Planner) Execute(_ context.Context, _ contracts.RemediationPlan) (contracts.ChangeArtifact, error) {
	return contracts.ChangeArtifact{}, fmt.Errorf("remediation: isolated change execution not implemented (phase P3)")
}
