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
	"fmt"
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

// Execute would apply the plan in an isolated workspace and return a
// ChangeArtifact. Not implemented in the scaffold: it returns an explicit error
// rather than fabricating a change (never claim a repair that did not happen).
func (Planner) Execute(_ context.Context, _ contracts.RemediationPlan) (contracts.ChangeArtifact, error) {
	return contracts.ChangeArtifact{}, fmt.Errorf("remediation: isolated change execution not implemented (phase P3)")
}
