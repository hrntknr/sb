package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func upstreamAuthMethods(identityFiles, certificateFiles []string) ([]cryptossh.AuthMethod, error) {
	identitySigners := identityFileSigners(identityFiles)
	agentSigners := sshAgentSigners()
	signers := append(append([]cryptossh.Signer{}, identitySigners...), agentSigners...)

	var auth []cryptossh.AuthMethod
	auth = appendPublicKeys(auth, certificateSigners(signers, certificateFiles))
	auth = appendPublicKeys(auth, identitySigners)
	auth = appendPublicKeys(auth, agentSigners)
	if len(auth) == 0 {
		return nil, fmt.Errorf("ssh: no upstream auth methods")
	}
	return auth, nil
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
		key, err := os.ReadFile(identityPath(path))
		if err != nil {
			continue
		}
		signer, err := cryptossh.ParsePrivateKey(key)
		if err == nil {
			signers = append(signers, signer)
		}
	}
	return signers
}

func sshAgentSigners() []cryptossh.Signer {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentClient := agent.NewClient(conn)
			if loaded, err := agentClient.Signers(); err == nil {
				return loaded
			}
		}
	}
	return nil
}

func certificateSigners(signers []cryptossh.Signer, certificateFiles []string) []cryptossh.Signer {
	var certSigners []cryptossh.Signer
	for _, path := range certificateFiles {
		certBytes, err := os.ReadFile(identityPath(path))
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
			certSigner, err := cryptossh.NewCertSigner(cert, signer)
			if err == nil {
				certSigners = append(certSigners, certSigner)
			}
		}
	}
	return certSigners
}

func identityPath(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if suffix, ok := strings.CutPrefix(path, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, suffix)
		}
	}
	return path
}
