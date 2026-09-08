package sshproxy

import (
	"fmt"
	"net"
	"os"

	"github.com/hrntknr/sb/internal/util"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// upstreamAuthMethods collects public key auth from the identity files and
// certificates and the ssh-agent listening on agentSocketPath. The returned
// agent connection (if any) must be closed once the upstream handshake is
// done; the signers sign through it.
func upstreamAuthMethods(config sshConfig, agentSocketPath string) ([]cryptossh.AuthMethod, net.Conn, error) {
	identitySigners := identityFileSigners(config.IdentityFiles)
	agentSigners, agentConn := sshAgentSigners(agentSocketPath)
	signers := append(append([]cryptossh.Signer{}, identitySigners...), agentSigners...)

	var auth []cryptossh.AuthMethod
	auth = appendPublicKeys(auth, certificateSigners(signers, config.CertificateFiles))
	auth = appendPublicKeys(auth, identitySigners)
	auth = appendPublicKeys(auth, agentSigners)
	if len(auth) == 0 {
		if agentConn != nil {
			agentConn.Close()
		}
		return nil, nil, fmt.Errorf("ssh: no upstream auth methods")
	}
	return auth, agentConn, nil
}

func appendPublicKeys(auth []cryptossh.AuthMethod, signers []cryptossh.Signer) []cryptossh.AuthMethod {
	if len(signers) == 0 {
		return auth
	}
	return append(auth, cryptossh.PublicKeys(signers...))
}

func identityFileSigners(identityFiles []string) []cryptossh.Signer {
	var signers []cryptossh.Signer
	for _, path := range identityFiles {
		key, err := os.ReadFile(util.ExpandHome(path))
		if err != nil {
			continue
		}
		if signer, err := cryptossh.ParsePrivateKey(key); err == nil {
			signers = append(signers, signer)
		}
	}
	return signers
}

func sshAgentSigners(socketPath string) ([]cryptossh.Signer, net.Conn) {
	if socketPath == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, nil
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, nil
	}
	return signers, conn
}

// certificateSigners pairs certificates with the signer of their matching key.
func certificateSigners(signers []cryptossh.Signer, certificateFiles []string) []cryptossh.Signer {
	var certSigners []cryptossh.Signer
	for _, path := range certificateFiles {
		certBytes, err := os.ReadFile(util.ExpandHome(path))
		if err != nil {
			continue
		}
		key, _, _, _, err := cryptossh.ParseAuthorizedKey(certBytes)
		if err != nil {
			continue
		}
		cert, ok := key.(*cryptossh.Certificate)
		if !ok {
			continue
		}
		for _, signer := range signers {
			if string(signer.PublicKey().Marshal()) != string(cert.Key.Marshal()) {
				continue
			}
			if certSigner, err := cryptossh.NewCertSigner(cert, signer); err == nil {
				certSigners = append(certSigners, certSigner)
			}
		}
	}
	return certSigners
}
