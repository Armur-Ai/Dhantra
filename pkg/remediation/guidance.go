package remediation

import (
	"fmt"
	"sort"
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// This file turns the *semantics* of a swarm AssessmentSnapshot into concrete,
// class-specific remediation guidance. The snapshot carries each finding node's
// attack class in Meta["class"] (bola/rce/ssrf/cred/leak/privesc/…); we map that
// to a CWE, a repair strategy, and specific fix steps — so a RemediationRequest
// and a `dhantra guide` run say *what kind of fix* each weakness needs, not just
// an opaque edge id. Nothing here changes code; it is advisory.

// Guidance is the class-specific remediation advice for a weakness type.
type Guidance struct {
	Class    string   `json:"class"`
	CWE      string   `json:"cwe"`
	Strategy string   `json:"strategy"` // root_cause | compensating_control | mitigation
	Summary  string   `json:"summary"`
	Steps    []string `json:"steps"`
	Count    int      `json:"count"` // number of verified weaknesses of this class in the snapshot
}

// guidanceTable maps an attack class to its canonical remediation guidance.
var guidanceTable = map[string]Guidance{
	"rce": {
		Class: "rce", CWE: "CWE-94", Strategy: "root_cause",
		Summary: "Remote code / command execution — eliminate the untrusted-input-to-interpreter path.",
		Steps: []string{
			"Remove dynamic eval / shell execution on request data; use safe library APIs instead of shelling out.",
			"If an interpreter is unavoidable, pass arguments as an argv array (never a concatenated string) and allowlist commands.",
			"Patch or replace unsafe deserialization (pickle/native) with a data-only format; reject untyped payloads.",
			"Run the component with least privilege and network egress denied by default.",
		},
	},
	"privesc": {
		Class: "privesc", CWE: "CWE-285", Strategy: "root_cause",
		Summary: "Broken function-level authorization (BFLA) — privilege escalation to a higher role.",
		Steps: []string{
			"Enforce authorization server-side on every privileged function, deny-by-default.",
			"Re-check the caller's role on each request; never rely on a hidden UI control or client-side gate.",
			"Separate admin routes and require an explicit admin capability, not just authentication.",
		},
	},
	"bola": {
		Class: "bola", CWE: "CWE-639", Strategy: "root_cause",
		Summary: "Broken object-level authorization (BOLA/IDOR) — cross-tenant/object access.",
		Steps: []string{
			"Enforce object ownership server-side: check the authenticated subject owns (or may access) every referenced object id.",
			"Never trust a client-supplied object id as authorization; scope queries to the caller.",
			"Prefer unguessable references and add per-request access checks at the data layer.",
		},
	},
	"cred": {
		Class: "cred", CWE: "CWE-287", Strategy: "root_cause",
		Summary: "Authentication / session / token weakness.",
		Steps: []string{
			"Verify token signature, algorithm, expiry and audience; reject alg:none and algorithm-confusion.",
			"Rotate any secret or key demonstrated as leaked, and invalidate sessions minted with it.",
			"Use short-lived tokens, secure+httpOnly cookies, and server-side session revocation.",
		},
	},
	"ssrf": {
		Class: "ssrf", CWE: "CWE-918", Strategy: "root_cause",
		Summary: "Server-side request forgery — the server can be made to call attacker-chosen destinations.",
		Steps: []string{
			"Allowlist outbound hosts/schemes for the feature; reject everything else.",
			"Block link-local and cloud-metadata ranges (169.254.0.0/16, fd00:ec2::254) and loopback.",
			"Do not follow redirects to internal targets; re-validate the final URL after each hop.",
			"Pair with an egress firewall so a bypass still cannot reach internal services.",
		},
	},
	"leak": {
		Class: "leak", CWE: "CWE-200", Strategy: "root_cause",
		Summary: "Sensitive information exposure (verbose errors, debug output, secret disclosure).",
		Steps: []string{
			"Remove sensitive data (secrets, tokens, internal detail) from responses and error bodies.",
			"Disable debug/verbose modes in production; return generic errors to clients.",
			"Scrub stack traces and internal identifiers; add output filtering at the response boundary.",
		},
	},
	"recon": {
		Class: "recon", CWE: "CWE-668", Strategy: "mitigation",
		Summary: "Exposed attack surface — reachable endpoints/resources that widen exposure.",
		Steps: []string{
			"Authenticate or remove unused/undocumented endpoints.",
			"Reduce the exposed surface (close ports, gate admin/diagnostic routes).",
		},
	},
}

// fallbackByKind maps a coarse edge kind to a class when the finding node
// carries no explicit class (e.g. a hand-built or older snapshot).
var fallbackByKind = map[string]string{
	"exploits":     "rce",
	"auth_as":      "cred",
	"leaks":        "leak",
	"escalates_to": "privesc",
	"reaches":      "recon",
}

// genericGuidance is used when neither the node class nor the edge kind is known.
var genericGuidance = Guidance{
	Class: "unclassified", CWE: "CWE-707", Strategy: "root_cause",
	Summary: "Unclassified weakness — validate and encode untrusted input at the sink.",
	Steps: []string{
		"Validate untrusted input against an allowlist at the trust boundary.",
		"Parameterize or safely encode data where it is interpreted (query/command/markup).",
	},
}

// classForEdge resolves the remediation class of a verified edge, preferring the
// target finding node's Meta["class"], then the edge kind.
func classForEdge(e contracts.GraphEdge, nodeClass map[string]string) string {
	if c := nodeClass[e.To]; c != "" {
		return c
	}
	if c := nodeClass[e.From]; c != "" {
		return c
	}
	if c := fallbackByKind[e.Kind]; c != "" {
		return c
	}
	return ""
}

// severityRank orders classes most-dangerous first for stable reporting.
func severityRank(class string) int {
	switch class {
	case "rce":
		return 0
	case "privesc":
		return 1
	case "ssrf":
		return 2
	case "bola":
		return 3
	case "cred":
		return 4
	case "leak":
		return 5
	case "recon":
		return 6
	default:
		return 7
	}
}

// SnapshotGuidance returns de-duplicated, severity-ordered remediation guidance
// for the *verified* weaknesses in a snapshot. Modeled-only edges are excluded —
// Dhantra advises on what was demonstrated, not what was merely hypothesized.
func SnapshotGuidance(snap contracts.AssessmentSnapshot) []Guidance {
	nodeClass := map[string]string{}
	for _, n := range snap.Nodes {
		if c := n.Meta["class"]; c != "" {
			nodeClass[n.ID] = c
		}
	}
	counts := map[string]int{}
	for _, e := range snap.Edges {
		if !e.Verified {
			continue
		}
		class := classForEdge(e, nodeClass)
		if class == "" {
			continue
		}
		counts[class]++
	}
	out := make([]Guidance, 0, len(counts))
	for class, n := range counts {
		g, ok := guidanceTable[class]
		if !ok {
			g = genericGuidance
			g.Class = class
		}
		g.Count = n
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := severityRank(out[i].Class), severityRank(out[j].Class); ri != rj {
			return ri < rj
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// RenderGuidanceMarkdown renders snapshot guidance as a reviewer-facing report.
func RenderGuidanceMarkdown(snap contracts.AssessmentSnapshot) string {
	gs := SnapshotGuidance(snap)
	var b strings.Builder
	fmt.Fprintf(&b, "# Remediation guidance — %s\n\n", snap.SnapshotID)
	if len(gs) == 0 {
		b.WriteString("_No verified weaknesses in the snapshot — nothing to remediate. " +
			"Modeled-only edges need confirmation before any change._\n")
		return b.String()
	}
	for _, g := range gs {
		fmt.Fprintf(&b, "## %s  ·  %s  ·  _%s_  (×%d)\n\n", strings.ToUpper(g.Class), g.CWE, g.Strategy, g.Count)
		fmt.Fprintf(&b, "%s\n\n", g.Summary)
		for _, s := range g.Steps {
			fmt.Fprintf(&b, "- %s\n", s)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// GuidanceSummaryLine is a one-line census of the verified classes, suitable for
// embedding in a RemediationRequest's Requirements text.
func GuidanceSummaryLine(snap contracts.AssessmentSnapshot) string {
	gs := SnapshotGuidance(snap)
	if len(gs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(gs))
	for _, g := range gs {
		parts = append(parts, fmt.Sprintf("%s×%d (%s)", g.Class, g.Count, g.CWE))
	}
	return "Verified weakness classes: " + strings.Join(parts, ", ") + "."
}
