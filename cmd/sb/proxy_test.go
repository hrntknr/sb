package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	v3 "github.com/hrntknr/sb/internal/config/v3"
)

// A corrupt upstream kubeconfig makes the k8s side's initial issuance
// fail; a working aws source keeps its side's loop alive through the
// failure. The aws change below triggers that loop while it lives.
func startProxyTestEnv(t *testing.T) (awsSource string, kubeconfigPath string) {
	t.Helper()
	home := t.TempDir()
	awsSource = filepath.Join(home, "source-config")
	credentials := filepath.Join(home, "source-credentials")
	t.Setenv("AWS_CONFIG_FILE", awsSource)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentials)
	if err := os.WriteFile(awsSource, []byte("[profile dev]\nregion = eu-west-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentials, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	kubeconfigPath = filepath.Join(t.TempDir(), "config")
	t.Setenv("KUBECONFIG", kubeconfigPath)
	return awsSource, kubeconfigPath
}

// TestStartProxyFailureStopsTheOtherSide covers the failed start: one
// side's issuance fails while the other side's loop still follows its
// source. Without the stop, the surviving loop would reissue what the
// failure removed; the start returns only once both sides stopped.
func TestStartProxyFailureStopsTheOtherSide(t *testing.T) {
	awsSource, kubeconfigPath := startProxyTestEnv(t)
	// The k8s side's source is corrupt: its initial issuance fails, the
	// failure the whole start returns.
	if err := os.WriteFile(kubeconfigPath, []byte("not yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	_, err := startProxy(ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err == nil {
		t.Fatal("startProxy() with a corrupt upstream kubeconfig; want a failure")
	}

	// The aws side's loop would follow this change while it lives: with
	// the start returned, it must be dead — the change reissues nothing.
	if err := os.WriteFile(awsSource, []byte("[profile dev]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForPathGone(t, filepath.Join(issueDir, ".aws"), 10*time.Second)
	if _, err := os.Stat(filepath.Join(issueDir, ".ssh")); !os.IsNotExist(err) {
		t.Fatalf(".ssh still exists after the failed start: %v", err)
	}
}

// TestStartProxyCancelledDuringStartup covers the run cancelled mid-startup:
// both sides' loops return without their issuance's result, and the start
// returns an error — never a server with a nil one, which the caller's
// Wait would dereference.
func TestStartProxyCancelledDuringStartup(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// Both sides start cleanly: their loops return nil when the run's
	// context is cancelled — a value that is not their issuance's result.
	if err := os.WriteFile(kubeconfigPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the run is cancelled before anything starts
	issueDir := t.TempDir()
	_, err := startProxy(ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err == nil {
		t.Fatal("startProxy() with a cancelled run; want a failure")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startProxy() = %v; want context.Canceled", err)
	}
	// Nothing the failed start issued stays behind it.
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, err := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after the failed start: %v", name, err)
		}
	}
}

// waitForPathGone fails the test if path appears within the deadline: what
// reappears there is a dead start's issuance, back from a loop that should
// not live past the start's return.
func waitForPathGone(t *testing.T, path string, deadline time.Duration) {
	t.Helper()
	start := time.Now()
	for time.Now().Before(start.Add(deadline)) {
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s reappeared; a dead start's issuance was reissued", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
