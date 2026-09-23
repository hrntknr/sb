package sshproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestKnownHostKeyNegotiation(t *testing.T) {
	signers := []cryptossh.Signer{testSigner(t)}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := cryptossh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signers = append(signers, rsaSigner)

	ca := testSigner(t)
	cert := &cryptossh.Certificate{Key: signers[1].PublicKey(), CertType: cryptossh.HostCert,
		ValidPrincipals: []string{"trusted.example"}, ValidBefore: cryptossh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := cryptossh.NewCertSigner(cert, signers[1])
	if err != nil {
		t.Fatal(err)
	}

	for _, trusted := range append(signers, certSigner) {
		t.Run(trusted.PublicKey().Type(), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			matchAddr := net.JoinHostPort("trusted.example", port)
			entry := knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(matchAddr))}, trusted.PublicKey())
			if trusted == certSigner {
				entry = "@cert-authority *.example " + string(cryptossh.MarshalAuthorizedKey(ca.PublicKey()))
			}
			config := sshConfig{Host: "127.0.0.1", Port: port, HostKeyAlias: "trusted.example",
				UserKnownHosts: []string{writeKnownHosts(t, entry)}, StrictHostKeyChecking: "yes"}
			serverConfig := &cryptossh.ServerConfig{NoClientAuth: true}
			for _, signer := range signers {
				serverConfig.AddHostKey(signer)
			}
			if trusted == certSigner {
				serverConfig.AddHostKey(certSigner)
			}
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, _, _, err := cryptossh.NewServerConn(conn, serverConfig)
				if err == nil {
					server.Close()
				}
				done <- err
			}()
			clientConfig := &cryptossh.ClientConfig{User: "test", Timeout: 5 * time.Second}
			if err := configureHostKey(config, clientConfig); err != nil {
				t.Fatal(err)
			}
			client, err := cryptossh.Dial("tcp", listener.Addr().String(), clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := clientConfig.HostKeyCallback(matchAddr, testAddr{}, testSigner(t).PublicKey()); err == nil {
				t.Fatal("untrusted key accepted")
			}
		})
	}
}
