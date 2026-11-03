package remediation

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestPlanRefusesWithoutAllowedChanges(t *testing.T) {
	_, err := Planner{}.Plan(context.Background(), contracts.RemediationRequest{RequestID: "r1"})
	if err == nil {
		t.Fatal("must refuse to plan with no allowed change classes (a score is not authorization)")
	}
}

func TestPlanProducesPlanWhenAuthorized(t *testing.T) {
	p, err := Planner{}.Plan(context.Background(), contracts.RemediationRequest{
		RequestID:      "r1",
		AllowedChanges: []string{"dependency_bump"},
		FindingRefs:    []string{"f1"},
		Source:         contracts.SourceRevisionRef{CommitID: "abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.PlanID == "" || p.RequestRef != "r1" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestExecuteDoesNotFabricateAChange(t *testing.T) {
	_, err := Planner{}.Execute(context.Background(), contracts.RemediationPlan{PlanID: "p1"})
	if err == nil {
		t.Fatal("scaffold Execute must not fabricate a ChangeArtifact")
	}
}

func TestDryRunProposesNotApplies(t *testing.T) {
	plan := contracts.RemediationPlan{PlanID: "p", BaseRevisions: []string{"base1"}}
	proposed := map[string][]byte{
		"go.mod":     []byte("module x\n"),
		"src/fix.go": []byte("package x"),
	}
	art, err := Planner{}.DryRun(plan, proposed)
	if err != nil {
		t.Fatal(err)
	}
	if art.ReviewState != "proposed" {
		t.Fatalf("dry-run must be 'proposed', got %q", art.ReviewState)
	}
	if art.PatchDigest == "" || len(art.ChangedPaths) != 2 {
		t.Fatalf("artifact incomplete: %+v", art)
	}
	if art.ChangedPaths[0] != "go.mod" || art.ChangedPaths[1] != "src/fix.go" {
		t.Fatalf("changed paths should be sorted: %v", art.ChangedPaths)
	}
	if art.BaseRevision != "base1" {
		t.Fatalf("base revision = %q", art.BaseRevision)
	}
	// deterministic digest for identical input
	art2, _ := Planner{}.DryRun(plan, proposed)
	if art2.PatchDigest != art.PatchDigest {
		t.Fatal("digest should be deterministic for identical input")
	}
}
