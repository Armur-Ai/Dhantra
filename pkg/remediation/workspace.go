package remediation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Workspace is an isolated, disposable directory where Dhantra prepares a change
// pinned to a base revision. All writes are confined to the workspace (no path
// traversal), and Cleanup removes it entirely — a remediation attempt never
// mutates the caller's tree in place.
type Workspace struct {
	dir  string
	base string
}

// NewWorkspace creates a fresh temp workspace tagged with the base revision it
// is pinned to. The caller must defer Cleanup.
func NewWorkspace(baseRevision string) (*Workspace, error) {
	dir, err := os.MkdirTemp("", "dhantra-ws-")
	if err != nil {
		return nil, fmt.Errorf("remediation: create workspace: %w", err)
	}
	return &Workspace{dir: dir, base: baseRevision}, nil
}

// Dir is the absolute workspace root.
func (w *Workspace) Dir() string { return w.dir }

// BaseRevision is the revision the workspace is pinned to.
func (w *Workspace) BaseRevision() string { return w.base }

// resolve maps a workspace-relative path to an absolute one, rejecting any
// attempt to escape the workspace (absolute paths, "..", symlink-style tricks).
func (w *Workspace) resolve(rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("remediation: empty path")
	}
	// Force the path to be workspace-relative, then join + verify containment.
	clean := filepath.Clean(string(filepath.Separator) + rel)
	full := filepath.Join(w.dir, clean)
	root := filepath.Clean(w.dir)
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return "", fmt.Errorf("remediation: path %q escapes the workspace", rel)
	}
	return full, nil
}

// WriteFile writes data to a workspace-relative path, creating parent dirs.
func (w *Workspace) WriteFile(rel string, data []byte) error {
	full, err := w.resolve(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0o644)
}

// ReadFile reads a workspace-relative path.
func (w *Workspace) ReadFile(rel string) ([]byte, error) {
	full, err := w.resolve(rel)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(full)
}

// Cleanup removes the workspace. Safe to call more than once.
func (w *Workspace) Cleanup() error {
	if w.dir == "" {
		return nil
	}
	err := os.RemoveAll(w.dir)
	w.dir = ""
	return err
}
