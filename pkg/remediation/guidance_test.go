package remediation

import (
	"strings"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func snapWith(nodes []contracts.GraphNode, edges []contracts.GraphEdge) contracts.AssessmentSnapshot {
	return contracts.AssessmentSnapshot{SnapshotID: "s1", Nodes: nodes, Edges: edges}
}

func TestSnapshotGuidance_UsesNodeClassAndOrdersBySeverity(t *testing.T) {
	nodes := []contracts.GraphNode{
		{ID: "f1", Meta: map[string]string{"class": "leak"}},
		{ID: "f2", Meta: map[string]string{"class": "rce"}},
	}
	edges := []contracts.GraphEdge{
		{ID: "e1", From: "entry", To: "f1", Kind: "leaks", Verified: true},
		{ID: "e2", From: "entry", To: "f2", Kind: "exploits", Verified: true},
	}
	gs := SnapshotGuidance(snapWith(nodes, edges))
	if len(gs) != 2 {
		t.Fatalf("expected 2 classes, got %d", len(gs))
	}
	if gs[0].Class != "rce" {
		t.Errorf("rce must sort before leak, got %q first", gs[0].Class)
	}
	if gs[0].CWE != "CWE-94" || gs[0].Strategy != "root_cause" {
		t.Errorf("rce guidance wrong: %+v", gs[0])
	}
}

func TestSnapshotGuidance_ExcludesModeledOnly(t *testing.T) {
	nodes := []contracts.GraphNode{{ID: "f1", Meta: map[string]string{"class": "ssrf"}}}
	edges := []contracts.GraphEdge{
		{ID: "e1", From: "entry", To: "f1", Kind: "leaks", Verified: false}, // modeled only
	}
	if gs := SnapshotGuidance(snapWith(nodes, edges)); len(gs) != 0 {
		t.Errorf("modeled-only edges must not produce guidance, got %+v", gs)
	}
}

func TestSnapshotGuidance_CountsAndFallbackKind(t *testing.T) {
	// Two verified bola edges (same class) → one guidance entry, Count 2.
	// One verified edge with no node class → falls back on kind "escalates_to" → privesc.
	nodes := []contracts.GraphNode{
		{ID: "f1", Meta: map[string]string{"class": "bola"}},
		{ID: "f2", Meta: map[string]string{"class": "bola"}},
		{ID: "f3"}, // no class
	}
	edges := []contracts.GraphEdge{
		{ID: "e1", From: "entry", To: "f1", Kind: "exploits", Verified: true},
		{ID: "e2", From: "entry", To: "f2", Kind: "exploits", Verified: true},
		{ID: "e3", From: "f3", To: "objective", Kind: "escalates_to", Verified: true},
	}
	gs := SnapshotGuidance(snapWith(nodes, edges))
	byClass := map[string]Guidance{}
	for _, g := range gs {
		byClass[g.Class] = g
	}
	if byClass["bola"].Count != 2 {
		t.Errorf("bola count = %d, want 2", byClass["bola"].Count)
	}
	if _, ok := byClass["privesc"]; !ok {
		t.Errorf("escalates_to with no node class should fall back to privesc; got %v", gs)
	}
}

func TestRenderGuidanceMarkdown_EmptyAndPopulated(t *testing.T) {
	empty := RenderGuidanceMarkdown(snapWith(nil, nil))
	if !strings.Contains(empty, "No verified weaknesses") {
		t.Errorf("empty render missing the honest no-op line:\n%s", empty)
	}
	nodes := []contracts.GraphNode{{ID: "f1", Meta: map[string]string{"class": "cred"}}}
	edges := []contracts.GraphEdge{{ID: "e1", From: "entry", To: "f1", Kind: "auth_as", Verified: true}}
	md := RenderGuidanceMarkdown(snapWith(nodes, edges))
	if !strings.Contains(md, "CRED") || !strings.Contains(md, "CWE-287") {
		t.Errorf("populated render missing class/CWE:\n%s", md)
	}
}

func TestGuidanceSummaryLine_EmbedsInRequest(t *testing.T) {
	nodes := []contracts.GraphNode{{ID: "f1", Meta: map[string]string{"class": "rce"}}}
	edges := []contracts.GraphEdge{{ID: "e1", From: "entry", To: "f1", Kind: "exploits", Verified: true}}
	req := RequestFromSnapshot(snapWith(nodes, edges))
	if !strings.Contains(req.Requirements, "rce×1 (CWE-94)") {
		t.Errorf("request requirements should name the verified class: %q", req.Requirements)
	}
}
