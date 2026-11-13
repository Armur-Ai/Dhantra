package remediation

import (
	"fmt"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// This file bridges Pentest Swarm → Dhantra. A scan emits an AssessmentSnapshot
// (`pentestswarm scan --format snapshot`); RequestFromSnapshot turns the
// *proven* parts of that graph into a RemediationRequest that `dhantra plan`
// can act on. Only verified edges become finding refs: Dhantra never proposes a
// change for a weakness that was merely modeled and not demonstrated — that
// stays an explicit assumption for a human to confirm, not a silent fix.

// RequestFromSnapshot derives a RemediationRequest from an AssessmentSnapshot.
// Verified edges (demonstrated weaknesses) become the finding refs; modeled-only
// edges are surfaced in Requirements so the plan can record them as unconfirmed
// rather than act on them.
func RequestFromSnapshot(snap contracts.AssessmentSnapshot) contracts.RemediationRequest {
	req := contracts.RemediationRequest{
		RequestID:             "rem-" + snap.SnapshotID,
		AllowedChanges:        []string{"code_fix", "config", "dependency_bump"},
		RequestedVerification: []string{"retest"},
	}
	if snap.Revision != "" {
		req.Source = contracts.SourceRevisionRef{CommitID: snap.Revision}
	}

	var modeledOnly int
	for _, e := range snap.Edges {
		if e.Verified {
			req.FindingRefs = append(req.FindingRefs, e.ID)
		} else {
			modeledOnly++
		}
	}

	switch {
	case len(req.FindingRefs) == 0 && modeledOnly == 0:
		req.Requirements = "No weaknesses in the snapshot. Nothing to remediate."
	case len(req.FindingRefs) == 0:
		req.Requirements = fmt.Sprintf(
			"No *verified* weaknesses to remediate; %d edge(s) are modeled only and need confirmation before any change.", modeledOnly)
	default:
		req.Requirements = fmt.Sprintf(
			"Remediate %d verified weakness(es) from the swarm assessment while preserving legitimate behavior. %d further edge(s) are modeled only and are out of scope until confirmed.",
			len(req.FindingRefs), modeledOnly)
	}
	return req
}
