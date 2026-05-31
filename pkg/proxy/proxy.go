package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	proxyk8s "github.com/hrntknr/secretbridge/pkg/proxy/k8s"
	proxyssh "github.com/hrntknr/secretbridge/pkg/proxy/ssh"
)

const DefaultProxyHost ProxyHost = "localhost"

type ProxyHost string

func (h ProxyHost) String() string {
	if h == "" {
		return string(DefaultProxyHost)
	}
	return string(h)
}

type Config struct {
	SSH proxyssh.Targets `yaml:"ssh"`
	K8s proxyk8s.Targets `yaml:"k8s"`
}

type Ports struct {
	SSH int
	K8s int
}

// Bundle groups domain-specific proxies.
type Bundle struct {
	SSH *proxyssh.Proxy
	K8s *proxyk8s.Proxy
}

// SyncConfig keeps proxy-only config files synced under dir.
func (s *Bundle) SyncConfig(ctx context.Context, host ProxyHost, ports Ports, dir string) error {
	if s == nil {
		return fmt.Errorf("proxy: nil Bundle")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	proxyHost := host.String()
	slog.Info("syncing proxy config", "host", proxyHost, "ssh_port", ports.SSH, "k8s_port", ports.K8s, "dir", dir)
	var wg sync.WaitGroup
	errc := make(chan error, 2)

	if s.SSH != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Debug("syncing ssh config")
			if err := s.SSH.SyncConfig(ctx, proxyHost, ports.SSH, dir); err != nil {
				errc <- fmt.Errorf("sync ssh credentials: %w", err)
			}
		}()
	}
	if s.K8s != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Debug("syncing k8s config")
			if err := s.K8s.SyncConfig(ctx, proxyHost, ports.K8s, dir); err != nil {
				errc <- fmt.Errorf("sync k8s credentials: %w", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case err := <-errc:
		cancel()
		<-done
		return err
	}
}
