package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var allowed = []string{"ssh-ed25519", "ssh-rsa"}

func TestParseSSHKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sk, _ := ssh.NewPublicKey(pub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk)))
	k, err := ParseSSHKey("  "+line+"  me@host  ", allowed, 3072)
	if err != nil || k.Comment != "me@host" || k.Line != line+" me@host" {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := ParseSSHKey(line, []string{"ssh-rsa"}, 3072); err == nil {
		t.Fatal("type filter")
	}
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	rk, _ := ssh.NewPublicKey(&r.PublicKey)
	if _, err := ParseSSHKey(string(ssh.MarshalAuthorizedKey(rk)), allowed, 3072); err == nil {
		t.Fatal("small RSA accepted")
	}
	if k, err := ParseSSHKey(string(ssh.MarshalAuthorizedKey(rk)), allowed, 2048); err != nil || k.Bits != 2048 {
		t.Fatal("RSA 2048 rejected with min 2048")
	}
	for _, bad := range []string{"", "garbage", "no-pty " + line} {
		if _, err := ParseSSHKey(bad, allowed, 1024); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if d := DescribeSSHKey("junk"); d.Fingerprint == DescribeSSHKey("other junk").Fingerprint {
		t.Fatal("unparseable keys share a fingerprint")
	}
}

func TestEscapeAndRealm(t *testing.T) {
	if got := escapeDN(`a,b+c=d "e"`); got != `a\,b\+c\=d \"e\"` {
		t.Fatalf("escape: %s", got)
	}
	if got := escapeDN(" #x "); got != `\ #x\ ` {
		t.Fatalf("escape edges: %q", got)
	}
	if realmFromBase("dc=idm,dc=specnet,dc=io") != "IDM.SPECNET.IO" {
		t.Fatal("realm")
	}
	if uidFromDN("uid=alice,cn=users,cn=accounts,dc=x") != "alice" || uidFromDN("cn=grp,dc=x") != "" {
		t.Fatal("uidFromDN")
	}
}
