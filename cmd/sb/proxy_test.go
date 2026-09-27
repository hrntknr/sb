package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hrntknr/sb/internal/awsproxy"
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

// writeK8sSource writes a usable source kubeconfig at path: what the k8s
// side's initial issuance reads.
func writeK8sSource(t *testing.T, path string) {
	t.Helper()
	content := "apiVersion: v1\nkind: Config\nclusters:\n" +
		"- name: dev\n  cluster:\n    server: https://127.0.0.1:6443\n    insecure-skip-tls-verify: true\n" +
		"users:\n- name: dev\n  user:\n    token: upstream-token\n" +
		"contexts:\n- name: dev\n  context:\n    cluster: dev\n    user: dev\ncurrent-context: dev\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startProxyBounded runs startProxy with a return bound: a start that does
// not return — a ready that never comes, an issuance that never begins —
// is a hung start, and the bound reports it instead of waiting forever.
func startProxyBounded(t *testing.T, ctx context.Context, cfg v3.Config, opts options, host, dir string) (*proxyServer, error) {
	t.Helper()
	type startResult struct {
		server *proxyServer
		err    error
	}
	done := make(chan startResult, 1)
	go func() {
		server, err := startProxy(ctx, cfg, opts, host, dir)
		done <- startResult{server, err}
	}()
	select {
	case r := <-done:
		return r.server, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("startProxy did not return: a ready that never comes held it")
		return nil, nil // not reached: Fatal ends the test
	}
}

// TestStartProxyFailureStopsTheOtherSide covers the failed start: one
// side's issuance fails while the other side's issuance still holds its
// session open. Without the stop, the surviving session would follow its
// source; the start returns only once both sides stopped.
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

	// The aws side's session is fixed: a source change would reissue
	// nothing here — nothing follows it within the session.
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

// TestStartProxyK8sSourceReadFailureIsReported covers the k8s side's
// source read failing: the kubeconfig path's parent exists as a file, so
// the load the initial issuance performs fails on it. The read's own
// failure must be the start's result: a start that waits for a ready
// that never comes would hang instead.
func TestStartProxyK8sSourceReadFailureIsReported(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// The kubeconfig's parent is a file: the source read's Load
	// fails on it. The aws source keeps its side's setup working.
	writeK8sSource(t, kubeconfigPath)
	blocker := t.TempDir()
	blockerFile := filepath.Join(blocker, "blocker")
	if err := os.WriteFile(blockerFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", filepath.Join(blockerFile, "config"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	_, err := startProxyBounded(t, ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err == nil {
		t.Fatal("startProxy() with a failing source read; want a failure")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("startProxy() = %v; want the source read's own failure", err)
	}
	// Nothing the failed start issued stays behind it.
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, statErr := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s still exists after the failed start: %v", name, statErr)
		}
	}
}

// TestStartProxyAWSSourceReadFailureIsReported covers the aws side's
// source read failing: the config file's parent exists as a file, so the
// profiles the initial issuance reads fail on it. The read's own
// failure must be the start's result: a start that waits for a ready
// that never comes would hang instead.
func TestStartProxyAWSSourceReadFailureIsReported(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// The k8s source stays working: the aws side's read is the failure.
	writeK8sSource(t, kubeconfigPath)
	blocker := t.TempDir()
	blockerFile := filepath.Join(blocker, "blocker")
	if err := os.WriteFile(blockerFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(blockerFile, "config"))

	// One aws rule: the aws side's initial issuance reads the source
	// profiles, so the read's failure is the start's result.
	cfg := v3.Config{AWS: []v3.AWSRule{{
		Profile:  "dev",
		RoleARN:  "arn:aws:iam::123456789012:role/dev",
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	_, err := startProxyBounded(t, ctx, cfg, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err == nil {
		t.Fatal("startProxy() with a failing source read; want a failure")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("startProxy() = %v; want the source read's own failure", err)
	}
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, statErr := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s still exists after the failed start: %v", name, statErr)
		}
	}
}

// TestStartProxyCancelledDuringReadyWait covers the run cancelled while
// the start waits for the k8s issuance's ready: the initial sync is stuck
// in the source read (the kubeconfig is a fifo with no writer), so the
// ready never comes. The cancellation must end the start: the cancelled
// run is a failed start, and what the hung issuance would write stays —
// the issuance it is still in the middle of is not waited out.
func TestStartProxyCancelledDuringReadyWait(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// The kubeconfig is a fifo: the k8s side's initial sync hangs in
	// the source read, and the ready it would signal never comes.
	if err := syscall.Mkfifo(kubeconfigPath, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(kubeconfigPath) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	go func() {
		time.Sleep(200 * time.Millisecond) // the initial sync is in the source read
		cancel()
	}()
	server, err := startProxyBounded(t, ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	_ = server
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startProxy() = %v; want context.Canceled", err)
	}
	// The issuing task did not exit within the deadline: its removal
	// would race what it is still writing. What was issued stays.
	if _, statErr := os.Stat(filepath.Join(issueDir, ".ssh")); os.IsNotExist(statErr) {
		t.Fatal(".ssh was removed while the issuing task is still writing")
	}
	// The read completes: the task's last write lands, then it exits on
	// the next select. Waiting for the write keeps this test's cleanup
	// from removing the issue dir while the write is still landing.
	first, rest := kubeconfigFifoParts()
	releaseFifo(t, kubeconfigPath, first, rest)
	waitForPathExists(t, filepath.Join(issueDir, ".kube", "config"))
}

// waitForPathExists fails the test if path does not appear within the
// deadline: the task's last write must land before the test ends.
func waitForPathExists(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never appeared; the task did not finish its last write", path)
}

// TestStartProxyAWSCancelledDuringReadyWait covers the same for the aws
// side: the source config is a fifo, so the initial sync's profile read
// (a config with aws targets reads the source) never completes.
func TestStartProxyAWSCancelledDuringReadyWait(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	writeK8sSource(t, kubeconfigPath) // the k8s side starts cleanly
	// One aws rule: the aws side's sync reads the source profiles.
	cfg := v3.Config{AWS: []v3.AWSRule{{
		Profile:  "dev",
		RoleARN:  "arn:aws:iam::123456789012:role/dev",
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}}
	sourcePath := os.Getenv("AWS_CONFIG_FILE")
	if err := os.Remove(sourcePath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(sourcePath, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(sourcePath) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	go func() {
		time.Sleep(200 * time.Millisecond) // the initial sync is in the source read
		cancel()
	}()
	server, err := startProxyBounded(t, ctx, cfg, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	_ = server
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startProxy() = %v; want context.Canceled", err)
	}
	if _, statErr := os.Stat(filepath.Join(issueDir, ".ssh")); os.IsNotExist(statErr) {
		t.Fatal(".ssh was removed while the issuing task is still writing")
	}
	// The read completes: the task's last write lands, then it exits on
	// the next select. Waiting for the write keeps this test's cleanup
	// from removing the issue dir while the write is still landing.
	releaseFifo(t, sourcePath, "[profile dev]\n", "region = eu-west-1\n")
	waitForPathExists(t, filepath.Join(issueDir, ".aws", "config"))
}

// TestStartProxyReportsTheUnfinishedReclamation covers the failed start's
// report: a cancellation with an issuing task stuck in its read — the
// reclamation cannot happen within the deadline — joins the unfinished
// reclamation and the issue dir to the startup error, so the caller sees
// what remains behind and how to reclaim it.
func TestStartProxyReportsTheUnfinishedReclamation(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// The kubeconfig is a fifo: the k8s side's initial sync hangs in
	// the source read, the ready never comes.
	if err := syscall.Mkfifo(kubeconfigPath, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(kubeconfigPath) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	go func() {
		time.Sleep(200 * time.Millisecond) // the initial sync is in the source read
		cancel()
	}()
	_, err := startProxyBounded(t, ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err == nil {
		t.Fatal("startProxy() with a cancelled run; want a failure")
	}
	// The startup error: the cancellation, joined with the failed
	// reclamation — what stays behind, and where it stays.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startProxy() = %v; want context.Canceled", err)
	}
	if !strings.Contains(err.Error(), "did not exit within") {
		t.Fatalf("startProxy() = %v; want the unfinished reclamation", err)
	}
	if !strings.Contains(err.Error(), issueDir) {
		t.Fatalf("startProxy() = %v; want the issue dir behind the failure", err)
	}
	// The issuing task did not exit: what it is still writing stays.
	if _, statErr := os.Stat(filepath.Join(issueDir, ".ssh")); os.IsNotExist(statErr) {
		t.Fatal(".ssh was removed while the issuing task is still writing")
	}
	// The read completes: the task's last write lands, then it exits on
	// the next select. Waiting for the write keeps this test's cleanup
	// from removing the issue dir while the write is still landing.
	first, rest := kubeconfigFifoParts()
	releaseFifo(t, kubeconfigPath, first, rest)
	waitForPathExists(t, filepath.Join(issueDir, ".kube", "config"))
}

// TestStopJoinsTheIssuanceTasks covers the normal stop's join: the fixed
// session issues nothing after the start, so the stop joins the issuing
// tasks at the deadline or before, and the deletion of what they issued
// happens only after they exited.
func TestStopJoinsTheIssuanceTasks(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// Both sides start cleanly: the issuances succeed, the start
	// returns a server both sides follow.
	writeK8sSource(t, kubeconfigPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	server, err := startProxy(ctx, v3.Config{}, options{sshListen: ":0", k8sListen: ":0", awsListen: ":0"}, "localhost", issueDir)
	if err != nil {
		t.Fatal(err)
	}

	// The source changes while the session runs. The fixed session does
	// not follow it: a change would land next session, so nothing puts
	// an issuance in flight here.
	if err := os.WriteFile(kubeconfigPath, []byte("apiVersion: v1\nkind: Config\ncontexts: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The stop joins the issuing tasks within the deadline: after the
	// initial issuance they wait for the stop, so they exit here.
	stopped := make(chan bool, 1)
	go func() { stopped <- server.Stop(shutdownCtx()) }()
	joined := <-stopped
	if !joined {
		t.Fatal("Stop() did not join the issuing tasks within the deadline")
	}
	// The deletion: what the issuing tasks wrote is gone after them.
	removeIssued(issueDir)

	// The join means the exit: nothing writes anymore. What the source
	// would have reissued after the deletion does not come back.
	writeK8sSource(t, kubeconfigPath)
	waitForPathGone(t, filepath.Join(issueDir, ".kube"), 5*time.Second)
	if _, err := os.Stat(filepath.Join(issueDir, ".ssh")); !os.IsNotExist(err) {
		t.Fatalf(".ssh exists after the removal: %v", err)
	}
}

func releaseFifo(t *testing.T, path, first, rest string) {
	t.Helper()
	writer, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(first); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := writer.WriteString(rest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

// kubeconfigFifoParts is a kubeconfig delivered in two parts: the read
// completes only at the last one, so what the read's completion triggers
// lands after it.
func kubeconfigFifoParts() (first, rest string) {
	return "apiVersion: v1\nkind: Config\nclusters:\n",
		"- name: dev\n  cluster:\n    server: https://127.0.0.1:9999\n    insecure-skip-tls-verify: true\n" +
			"users:\n- name: dev\n  user:\n    token: upstream-token\n" +
			"contexts:\n- name: dev\n  context:\n    cluster: dev\n    user: dev\ncurrent-context: dev\n"
}
