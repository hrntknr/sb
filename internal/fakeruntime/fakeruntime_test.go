package fakeruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrntknr/sb/internal/containers"
)

// TestFakesAnswerRuntimeCalls covers the fakes' container-runtime behavior:
// listing by label, removing by id, and the apple JSON list.
func TestFakesAnswerRuntimeCalls(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "cid1 sb.session.id=sidA\n")

	// ListSession by label finds it; another session's label does not.
	if ids, err := containers.ListSession(context.Background(), containers.Docker, "sidA"); err != nil || len(ids) != 1 || ids[0] != "cid1" {
		t.Fatalf("ListSession(docker, sidA) = %v, %v; want [cid1]", ids, err)
	}
	if ids, err := containers.ListSession(context.Background(), containers.Docker, "sidB"); err != nil || len(ids) != 0 {
		t.Fatalf("ListSession(docker, sidB) = %v, %v; want empty", ids, err)
	}

	// RemoveSession stops and removes by label.
	if err := containers.RemoveSession(context.Background(), containers.Docker, "sidA"); err != nil {
		t.Fatalf("RemoveSession: %v", err)
	}
	if state := stateText(t); strings.Contains(state, "cid1") {
		t.Fatalf("state after RemoveSession: %q; cid1 gone", state)
	}
	// The calls log records the listing and the removal.
	calls := callsText(t)
	if !strings.Contains(calls, "ps -aq --filter label=sb.session.id=sidA") {
		t.Fatalf("calls log %q: no ps -aq --filter label=sb.session.id=sidA", calls)
	}
	if !strings.Contains(calls, "rm -f cid1") {
		t.Fatalf("calls log %q: no rm -f cid1", calls)
	}
}

func TestFakesRunRegistersAndWritesCidfile(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "old sb.session.id=oldsid\n")

	// run registers the container, writes the cidfile, and lives until stdin
	// closes (an empty stdin in tests: right away).
	cidfile := t.TempDir() + "/cid"
	fake(t, "docker", "run --rm --cidfile "+cidfile+" --label sb.session.id=sidNew --init ghcr.io/hrntknr/sh:full zsh -l")
	if cid := strings.TrimSpace(read(t, cidfile)); cid != "fake-container-1" {
		t.Fatalf("cidfile = %q; want fake-container-1", cid)
	}
	if state := stateText(t); !strings.Contains(state, "fake-container-1 sb.session.id=sidNew\n") {
		t.Fatalf("state after run: %q; want the container with the sb label", state)
	}

	// The next run takes the next id; the old container is untouched.
	cidfile2 := t.TempDir() + "/cid"
	fake(t, "docker", "run --cidfile "+cidfile2+" --label sb.session.id=sidNew image")
	if cid := strings.TrimSpace(read(t, cidfile2)); cid != "fake-container-2" {
		t.Fatalf("cidfile2 = %q; want fake-container-2", cid)
	}
	if state := stateText(t); !strings.Contains(state, "old sb.session.id=oldsid\n") {
		t.Fatalf("state: %q; the old container stayed", state)
	}
}

// TestFakesAppleListsJSON exercises the apple CLI: ls --all --format json
// from the state, with the sb label from the state lines.
func TestFakesAppleListsJSON(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "cid1 sb.session.id=sidA\ncidX other-label\n")

	if ids, err := containers.ListSession(context.Background(), containers.Apple, "sidA"); err != nil || len(ids) != 1 || ids[0] != "cid1" {
		t.Fatalf("ListSession(apple, sidA) = %v, %v; want [cid1] only", ids, err)
	}
}

func TestFakesExecAnswersByContainerID(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "cid1 sb.session.id=sidA\n")

	// exec with a container the state knows exits 0; an unknown id 1.
	if err := fake(t, "docker", "exec -i -t cid1 zsh -l"); err != nil {
		t.Fatalf("exec into a known container: %v", err)
	}
	if err := fake(t, "docker", "exec -i -t cidX zsh -l"); err == nil {
		t.Fatal("exec into an unknown container: no error")
	}
}

// fake runs a fake runtime CLI with args (whitespace-split) and returns its
// exit error.
func fake(t *testing.T, binary, args string) error {
	t.Helper()
	t.Logf("fake %s %s", binary, args)
	cmd := exec.Command(binary, strings.Fields(args)...)
	cmd.Stdin = nil // empty stdin: run's lifetime ends at once
	return cmd.Run()
}

func setState(t *testing.T, lines string) {
	t.Helper()
	if err := os.WriteFile(os.Getenv("SB_FAKE_STATE"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stateText(t *testing.T) string {
	t.Helper()
	return read(t, os.Getenv("SB_FAKE_STATE"))
}

func callsText(t *testing.T) string {
	t.Helper()
	return read(t, os.Getenv("SB_TEST_CALLS_LOG"))
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestFakesRunWithLifetime covers the lifetime path: with
// SB_FAKE_RUN_LIFETIME set, run stays alive until the file is gone.
func TestFakesRunWithLifetime(t *testing.T) {
	dir := t.TempDir()
	Install(t, dir)
	lifetime := filepath.Join(dir, "lifetime")
	if err := os.WriteFile(lifetime, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_RUN_LIFETIME", lifetime)
	cidfile := filepath.Join(t.TempDir(), "cid")
	done := make(chan error, 1)
	go func() {
		cmd := exec.Command("docker", strings.Fields("run --cidfile "+cidfile+" --label sb.session.id=sidA image")...)
		cmd.Stdin = nil
		done <- cmd.Run()
	}()
	// The run stays alive while the lifetime file exists.
	select {
	case err := <-done:
		t.Fatalf("run ended while the lifetime file exists: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := os.Remove(lifetime); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run never ended after the lifetime file was removed")
	}
}

// TestRemoveSessionKillsStalledRuntime covers a runtime that does not
// answer: the listing by label never returns, so sb's deadline kills the
// CLI and the removal fails — the containers stay for the recovery path.
func TestRemoveSessionKillsStalledRuntime(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "cid1 sb.session.id=sidA\n")
	// The CLI never answers while this exists.
	stall := filepath.Join(t.TempDir(), "stall")
	if err := os.WriteFile(stall, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_STALL", stall)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := containers.RemoveSession(ctx, containers.Docker, "sidA")
	if err == nil {
		t.Fatal("RemoveSession() with a stalled runtime, want error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "killed") {
		t.Fatalf("RemoveSession() error = %v; want the deadline kill", err)
	}
	// The call reached the CLI before it stalled.
	if calls := callsText(t); !strings.Contains(calls, "ps -aq --filter label=sb.session.id=sidA") {
		t.Fatalf("calls log %q: no listing by label", calls)
	}
	// The containers stay for the recovery path.
	if state := stateText(t); !strings.Contains(state, "cid1 sb.session.id=sidA\n") {
		t.Fatalf("state = %q; the stalled removal dropped the containers", state)
	}
}

// TestRemoveSessionDetectsLingeringRuntime covers a runtime that answers
// without removing: the listing after the call still finds the containers,
// which is a failed removal — the containers stay for the recovery path.
func TestRemoveSessionDetectsLingeringRuntime(t *testing.T) {
	Install(t, t.TempDir())
	setState(t, "cid1 sb.session.id=sidA\n")
	linger := filepath.Join(t.TempDir(), "linger")
	if err := os.WriteFile(linger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_FAKE_RM_LINGER", linger)

	if err := containers.RemoveSession(context.Background(), containers.Docker, "sidA"); err == nil {
		t.Fatal("RemoveSession() with a lingering runtime, want error")
	} else if !strings.Contains(err.Error(), "left containers behind") {
		t.Fatalf("RemoveSession() error = %q; want the leftover containers", err.Error())
	}
	// The containers stay behind the call.
	if state := stateText(t); !strings.Contains(state, "cid1 sb.session.id=sidA\n") {
		t.Fatalf("state = %q; the lingering removal dropped the containers", state)
	}
}
