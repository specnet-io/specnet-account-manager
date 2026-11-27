package directory

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHKey is a parsed, validated public key.
type SSHKey struct {
	Line        string // normalised authorized_keys line: "type base64 comment"
	Type        string
	Bits        int
	Comment     string
	Fingerprint string
}

// ParseSSHKey validates one authorized_keys line against allowed types and minimum RSA size.
func ParseSSHKey(line string, allowed []string, rsaMinBits int) (*SSHKey, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("paste a public key (the contents of a .pub file)")
	}
	if strings.Contains(line, "PRIVATE KEY") {
		return nil, errors.New("that is a private key: never share it. Paste the .pub file instead")
	}
	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, errors.New("not a valid OpenSSH public key")
	}
	if len(options) > 0 {
		return nil, errors.New("key options (from=, command=, ...) are not allowed")
	}
	k := &SSHKey{Type: pub.Type(), Comment: strings.TrimSpace(comment), Fingerprint: ssh.FingerprintSHA256(pub)}
	ok := false
	for _, a := range allowed {
		if a == k.Type {
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("key type %s is not allowed here", k.Type)
	}
	if cp, isCrypto := pub.(ssh.CryptoPublicKey); isCrypto {
		if rk, isRSA := cp.CryptoPublicKey().(*rsa.PublicKey); isRSA {
			k.Bits = rk.N.BitLen()
			if k.Bits < rsaMinBits {
				return nil, fmt.Errorf("RSA keys must be at least %d bits (this one is %d)", rsaMinBits, k.Bits)
			}
		}
	}
	k.Line = strings.TrimSpace(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + k.Comment)
	return k, nil
}

// DescribeSSHKey parses a stored key for display; unknown formats are shown raw.
func DescribeSSHKey(line string) *SSHKey {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return &SSHKey{Line: line, Type: "unknown", Fingerprint: "raw:" + secretHash(line)[:16]}
	}
	k := &SSHKey{Line: line, Type: pub.Type(), Comment: comment, Fingerprint: ssh.FingerprintSHA256(pub)}
	if cp, ok := pub.(ssh.CryptoPublicKey); ok {
		if rk, ok := cp.CryptoPublicKey().(*rsa.PublicKey); ok {
			k.Bits = rk.N.BitLen()
		}
	}
	return k
}

func secretHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
