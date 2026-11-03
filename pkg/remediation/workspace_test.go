package remediation

import (
	"os"
	"testing"
)

func TestWorkspaceWriteReadCleanup(t *testing.T) {
	w, err := NewWorkspace("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if w.BaseRevision() != "abc123" {
		t.Fatalf("base = %q", w.BaseRevision())
	}
	if err := w.WriteFile("src/main.go", []byte("package main")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := w.ReadFile("src/main.go")
	if err != nil || string(got) != "package main" {
		t.Fatalf("read back failed: %q %v", got, err)
	}
	dir := w.Dir()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("workspace dir should exist: %v", err)
	}
	if err := w.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("workspace should be gone after cleanup")
	}
	if err := w.Cleanup(); err != nil {
		t.Fatalf("second cleanup should be safe: %v", err)
	}
}

func TestWorkspaceRejectsTraversal(t *testing.T) {
	w, _ := NewWorkspace("base")
	defer w.Cleanup()
	for _, bad := range []string{"../escape", "../../etc/passwd", "a/../../b"} {
		if err := w.WriteFile(bad, []byte("x")); err == nil {
			t.Fatalf("path %q should be rejected", bad)
		}
	}
	// a benign nested path is fine
	if err := w.WriteFile("a/b/c.txt", []byte("x")); err != nil {
		t.Fatalf("benign nested path should work: %v", err)
	}
}
