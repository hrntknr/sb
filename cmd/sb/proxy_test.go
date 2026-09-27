package main

import (
	"context"
	"errors"
	"net"
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

// proxyTestConfig returns a config with one rule per protocol in use:
// ssh and k8s. The aws issuance's startup resolves its sessions against
// the source, so a test that wants the aws protocol in use provides a
// working source for it and adds its rule on its own.
func proxyTestConfig() v3.Config {
	return v3.Config{
		SSH: []v3.SSHRule{{Host: "github.com"}},
		K8s: []v3.K8sRule{{Context: "dev", Resources: []v3.ResourceRule{{
			Group: "", Resource: "namespaces", Namespace: "*", Scope: "cluster", Verbs: []string{"get", "list"},
		}}}},
	}
}

// startProxyBounded runs startProxy with a return bound: a start that does
// not return — a ready that never comes, an issuance that never begins —
// is a hung start, and the bound reports it instead of waiting forever.
func startProxyBounded(t *testing.T, ctx context.Context, cfg v3.Config, sshAddr, k8sAddr, awsAddr, host, dir string) (*proxyServer, error) {
	t.Helper()
	type startResult struct {
		server *proxyServer
		err    error
	}
	done := make(chan startResult, 1)
	go func() {
		server, err := startProxy(ctx, cfg, sshAddr, k8sAddr, awsAddr, host, dir)
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
	// One rule per protocol in use: the ssh and k8s sides start, and the
	// aws side's issuance starts too — the failure stops it mid-flight.
	cfg := proxyTestConfig()
	cfg.AWS = []v3.AWSRule{{
		Profile:  "dev",
		RoleARN:  "arn:aws:iam::123456789012:role/dev",
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}
	_, err := startProxy(ctx, cfg, ":0", ":0", ":0", "localhost", issueDir)
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
	// One rule per protocol in use: the cancelled run is a failed start
	// for every protocol, and nothing the failed start issued stays.
	cfg := proxyTestConfig()
	cfg.AWS = []v3.AWSRule{{
		Profile:  "dev",
		RoleARN:  "arn:aws:iam::123456789012:role/dev",
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}
	_, err := startProxy(ctx, cfg, ":0", ":0", ":0", "localhost", issueDir)
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

// TestStartProxyStartsOnlyConfiguredProtocols covers the protocol set the
// start serves: only the protocols the configuration has rules for are
// started. The k8s source is corrupt here — a k8s protocol in use would
// fail the start on it; the protocol is not in use, so its source is
// never read, and the start succeeds. The protocols not in use issue
// nothing: only the ssh protocol's credentials are under the dir, and
// the stop joins nothing that never started.
func TestStartProxyStartsOnlyConfiguredProtocols(t *testing.T) {
	_, kubeconfigPath := startProxyTestEnv(t)
	// The k8s source is corrupt: a k8s protocol in use would fail the
	// start on it.
	if err := os.WriteFile(kubeconfigPath, []byte("not yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	// Only the ssh protocol is in use: one ssh rule.
	cfg := v3.Config{SSH: []v3.SSHRule{{Host: "github.com"}}}
	server, err := startProxy(ctx, cfg, ":0", ":0", ":0", "localhost", issueDir)
	if err != nil {
		t.Fatalf("startProxy() = %v; want a start that skips the k8s read", err)
	}

	// Only the ssh protocol's issuance is under the dir: the protocols
	// not in use issued nothing.
	if _, err := os.Stat(filepath.Join(issueDir, ".ssh")); err != nil {
		t.Fatal(".ssh was not issued; want the ssh protocol's issuance")
	}
	for _, name := range []string{".kube", ".aws"} {
		if _, err := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was issued; the protocol is not in use", name)
		}
	}

	// The stop joins nothing that never started: it reports true.
	if !server.Stop(shutdownCtx()) {
		t.Fatal("Stop() reported false; nothing is waited for that never started")
	}
}

// TestStartProxyWithoutProtocols covers the configuration with no rules
// at all: no protocol is in use, so nothing is started, issued, or read.
// The corrupt sources would fail a start that read them; this start
// does not, and the stop joins nothing — the empty set exits within any
// deadline.
func TestStartProxyWithoutProtocols(t *testing.T) {
	awsSource, kubeconfigPath := startProxyTestEnv(t)
	// Both sources are corrupt: a protocol in use would fail the start
	// on its source.
	if err := os.WriteFile(kubeconfigPath, []byte("not yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(awsSource, []byte("["), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	server, err := startProxy(ctx, v3.Config{}, ":0", ":0", ":0", "localhost", issueDir)
	if err != nil {
		t.Fatalf("startProxy() = %v; want a start that starts nothing", err)
	}
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, err := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was issued; the protocol is not in use", name)
		}
	}
	if !server.Stop(shutdownCtx()) {
		t.Fatal("Stop() reported false; nothing is waited for that never started")
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
	_, err := startProxyBounded(t, ctx, proxyTestConfig(), ":0", ":0", ":0", "localhost", issueDir)
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
	_, err := startProxyBounded(t, ctx, cfg, ":0", ":0", ":0", "localhost", issueDir)
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
	server, err := startProxyBounded(t, ctx, proxyTestConfig(), ":0", ":0", ":0", "localhost", issueDir)
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
	// One aws rule: the aws side's startup resolves the role's upstream —
	// an STS call — before the ready; connections hang in it, so the
	// ready never comes and the start waits for it.
	cfg := v3.Config{AWS: []v3.AWSRule{{
		Profile:  "dev",
		RoleARN:  "arn:aws:iam::123456789012:role/dev",
		Services: []awsproxy.Service{{Name: "dynamodb", Mode: "ro"}},
	}}}
	// The source provides the profile's credentials: the STS call signs
	// with them.
	if err := os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[dev]\naws_access_key_id = SOURCE\naws_secret_access_key = source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Connections hang in this endpoint: the STS call the resolution
	// makes never completes.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", "http://"+blocker.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issueDir := t.TempDir()
	go func() {
		time.Sleep(200 * time.Millisecond) // the startup resolution is in the STS call
		cancel()
	}()
	server, err := startProxyBounded(t, ctx, cfg, ":0", ":0", ":0", "localhost", issueDir)
	_ = server
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startProxy() = %v; want context.Canceled", err)
	}
	// The issuance's STS call was cut by the cancellation, so its task
	// exits and nothing it issued stays behind the failed start.
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, statErr := os.Stat(filepath.Join(issueDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s still exists after the failed start: %v", name, statErr)
		}
	}
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
	_, err := startProxyBounded(t, ctx, proxyTestConfig(), ":0", ":0", ":0", "localhost", issueDir)
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
	server, err := startProxy(ctx, proxyTestConfig(), ":0", ":0", ":0", "localhost", issueDir)
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
	// A failing deletion joins the run's result; nothing stays silently.
	if err := removeIssued(issueDir); err != nil {
		t.Fatalf("removeIssued() error = %v", err)
	}

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

// TestProxyExposureRequiresHostBeyondLoopback covers the exposure check:
// listening beyond loopback must carry --host — the credentials point
// downstreams at the host they reach the proxy at, and it must be given.
// Loopback listens need nothing: the defaults bind loopback.
func TestProxyExposureRequiresHostBeyondLoopback(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"no flags: defaults bind loopback", nil, false},
		{"loopback listen", []string{"--ssh-listen", "127.0.0.1:2222"}, false},
		{"wildcard listen", []string{"--ssh-listen", "0.0.0.0:2222"}, true},
		{"all-interfaces listen", []string{"--ssh-listen", ":2222"}, true},
		{"named listen", []string{"--aws-listen", "proxy.example:0"}, true},
		{"address listen", []string{"--k8s-listen", "192.168.1.5:6443"}, true},
		{"wildcard listen with --host", []string{"--ssh-listen", ":2222", "--host", "proxy.example"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &options{}
			cmd := newProxyCommand(opts)
			if err := cmd.Flags().Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			err := checkProxyExposure(cmd, *opts)
			if tt.wantErr && err == nil {
				t.Fatal("checkProxyExposure() = nil; want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("checkProxyExposure() = %v; want no error", err)
			}
		})
	}
}

// TestProxyExposureRejectsWildcardHost covers the host half of the exposure
// check: the host written into the credentials must be a destination. A
// wildcard address (0.0.0.0, ::) listens; nothing connects to it.
func TestProxyExposureRejectsWildcardHost(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "[::]"} {
		opts := &options{}
		cmd := newProxyCommand(opts)
		if err := cmd.Flags().Parse([]string{"--host", host}); err != nil {
			t.Fatal(err)
		}
		if err := checkProxyExposure(cmd, *opts); err == nil {
			t.Fatalf("checkProxyExposure(--host %q) = nil; want an error", host)
		}
	}
	for _, host := range []string{"localhost", "proxy.example", "127.0.0.1", "::1"} {
		opts := &options{}
		cmd := newProxyCommand(opts)
		if err := cmd.Flags().Parse([]string{"--host", host}); err != nil {
			t.Fatal(err)
		}
		if err := checkProxyExposure(cmd, *opts); err != nil {
			t.Fatalf("checkProxyExposure(--host %q) = %v; want no error", host, err)
		}
	}
}

// TestRemoveIssued covers the reclamation's own contract: the three
// subtrees sb issued are removed, anything else in the dir stays, and
// the removal reports what could not be removed instead of dropping
// it in a log line.
func TestRemoveIssued(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{".ssh/config", ".ssh/id_ed25519", ".ssh/known_hosts", ".kube/config", ".aws/credentials"} {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Someone else's file in the same dir: not sb's to delete.
	if err := os.WriteFile(filepath.Join(dir, "own.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeIssued(dir); err != nil {
		t.Fatalf("removeIssued() error = %v", err)
	}
	for _, name := range []string{".ssh", ".kube", ".aws"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after the removal: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "own.txt")); err != nil {
		t.Fatalf("own.txt did not survive the removal: %v", err)
	}
}
