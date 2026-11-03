# Dhantra — Roadmap

> Planning document. Each phase ships a usable standalone increment. Status: ☐
> planned · ◐ in progress · ☑ done. All ☐ today (fresh scaffold).

## Phase 0 — Foundations
- ☐ Go module `github.com/Armur-Ai/Dhantra`; `pkg/` engine + `cmd/dhantra` CLI.
- ☐ Core types: **RemediationRequest** (in), **ChangePlan**, **ChangeArtifact** (out), **VerificationResult**.
- ☐ Import adapter for RemediationRequests (from Engira or a versioned file), with explicit scope / allowed change classes / constraints / approval policy.
- ☐ LICENSE, CI (build + `go test ./...`).

## Phase 1 — Isolation substrate (safety first)
- ◐ Isolated temp workspace pinned to a base revision, write-bounded (no traversal), guaranteed cleanup (pkg/remediation Workspace).
- ☐ Enforcing build/execution isolation profile (no host Docker socket, no broad home mount, no production/cloud creds); resource/network/filesystem limits outside the model.
- ☐ Hostile-build-script fixture test (prove containment; regex filters are not containment).

## Phase 2 — Remediation planning
- ☐ Turn an approved request into a concrete change plan within allowed change classes.
- ☐ Block affected changes on unknown repo/branch mapping or missing policy (not unrelated read-only analysis).
- ☐ Optional AI planning with approved, minimized source context; deterministic fallback always available; model output never auto-confirms or expands scope.

## Phase 3 — Change execution & artifacts
- ☐ Apply changes in the sandbox; produce a `ChangeArtifact` (base revision, patch digest, changed paths, lockfile changes, proposed commits, agent attribution).
- ☐ Never forge a human signature or claim founder authorship of an automated change.
- ☐ No unrelated dependency/lockfile churn.

## Phase 4 — Verification orchestration
- ☐ Request Trishul rescan of changed source; collect code/dependency evidence.
- ☐ Request scoped dynamic retest via Engira → Swarm where relevant.
- ☐ Assemble before/after repair evidence; bind change → build → deployment where supported.

## Phase 5 — Lifecycle & hardening
- ☐ Idempotent, cancellable jobs; opaque job refs; purpose-limited evidence access.
- ☐ "Change is not proof of repair" framing enforced in all outputs.
- ☐ Architecture doc + suite topology (Mermaid).

## Non-goals
- Not a SOC/SIEM/EDR; no monitoring or incident response. No discovery (Hayagriva), scoring/reporting (Engira), exploitation (Swarm), or code analysis (Trishul). Dhantra plans, executes, and verifies remediation.
