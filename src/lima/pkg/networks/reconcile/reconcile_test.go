package networks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lima-vm/lima/pkg/templatestore"
)

func TestReconcileWithOrphanedInstance(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("network reconciliation is macOS-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LIMA_HOME", home)
	for _, name := range []string{"_config", "docker", "test-alpine"} {
		if err := os.Mkdir(filepath.Join(home, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// An empty network map prevents reconciliation from managing host services.
	if err := os.WriteFile(filepath.Join(home, "_config", "networks.yaml"), []byte("networks: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := templatestore.Read("alpine")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "docker", "lima.yaml"), config, 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "test-alpine", "leftover")
	if err := os.WriteFile(marker, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("unrelated missing configuration does not block start", func(t *testing.T) {
		if err := Reconcile(context.Background(), "docker"); err != nil {
			t.Fatalf("unrelated orphan blocked reconciliation: %v", err)
		}
		data, err := os.ReadFile(marker)
		if err != nil || string(data) != "preserve" {
			t.Fatalf("orphan contents changed: %q, %v", data, err)
		}
	})
	t.Run("requested missing configuration remains an error", func(t *testing.T) {
		if err := Reconcile(context.Background(), "test-alpine"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want missing instance configuration error", err)
		}
	})
}
