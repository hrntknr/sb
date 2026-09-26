package util

import (
	"crypto/x509"
	"testing"
)

func TestIssueCertificate(t *testing.T) {
	for _, host := range []string{"proxy.example.dev", "127.0.0.1"} {
		certificate, err := IssueCertificate(host)
		if err != nil {
			t.Fatalf("IssueCertificate(%q): %v", host, err)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatalf("IssueCertificate(%q): %v", host, err)
		}
		var covered bool
		for _, name := range leaf.DNSNames {
			covered = covered || name == host
		}
		for _, ip := range leaf.IPAddresses {
			covered = covered || ip.String() == host
		}
		if !covered {
			t.Errorf("IssueCertificate(%q): certificate does not cover the host", host)
		}
	}
}
