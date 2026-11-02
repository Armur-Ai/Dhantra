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
