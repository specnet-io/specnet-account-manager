package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
)

// The signed-in landing page: message of the day, platform links, CA downloads. See DETAILS.md §Home page.

type certView struct {
	ID          string // first 16 hex chars of the SHA-256 fingerprint; the download path
	Name        string
	Root        bool
	NotAfter    time.Time
	Fingerprint string // SHA-256, colon separated
	File        string // download filename
	der         []byte
}

func (s *Server) userHome(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "home", "home")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dir, dirErr := s.Dir()

	if s.settings.Bool("home_motd_enabled") {
		name := s.settings.Get("home_motd_group")
		if dirErr != nil {
			p.Data["MotdNote"] = "Directory not configured."
		} else if g, err := dir.GetGroup(ctx, name); err == nil {
			p.Data["Motd"] = strings.TrimSpace(g.Description)
		} else if errors.Is(err, directory.ErrNotFound) {
			p.Data["MotdNote"] = "Group " + name + " not found: create it and set its description."
		} else {
			s.log.Warn("motd", "group", name, "err", err)
			p.Data["MotdNote"] = "Could not read the message of the day."
		}
	}
	p.Data["Links"], _ = settings.ParseLinks(s.settings.Get("home_links"))
	if s.settings.Bool("home_certs_enabled") {
		p.Data["CertsShown"] = true
		p.Data["Certs"] = s.caCerts(ctx, dir, dirErr)
	}
	s.render(w, r, http.StatusOK, "start", p)
}

// caCerts is the directory's CA store, or the ldap_ca_cert setting when that is empty; roots first.
func (s *Server) caCerts(ctx context.Context, dir directory.Directory, dirErr error) []certView {
	var ders [][]byte
	if dirErr == nil {
		var err error
		if ders, err = dir.CACertificates(ctx); err != nil {
			s.log.Warn("read CA certificates", "err", err)
		}
	}
	if len(ders) == 0 {
		rest := []byte(s.settings.Get("ldap_ca_cert"))
		for {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			if b.Type == "CERTIFICATE" {
				ders = append(ders, b.Bytes)
			}
		}
	}
	seen := map[string]bool{}
	var out []certView
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil || !c.IsCA {
			continue
		}
		sum := sha256.Sum256(der)
		id := hex.EncodeToString(sum[:8])
		if seen[id] {
			continue
		}
		seen[id] = true
		name := c.Subject.CommonName
		if name == "" {
			name = c.Subject.String()
		}
		fp := strings.ToUpper(hex.EncodeToString(sum[:]))
		var b strings.Builder
		for i := 0; i < len(fp); i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(fp[i : i+2])
		}
		out = append(out, certView{
			ID: id, Name: name, NotAfter: c.NotAfter, Fingerprint: b.String(), der: der,
			Root: bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil,
			File: fileSafe(name) + ".crt",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Root != out[j].Root {
			return out[i].Root
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func fileSafe(name string) string {
	f := strings.Trim(unsafeFile.ReplaceAllString(name, "-"), "-.")
	if f == "" {
		f = "ca"
	}
	return f
}

// certDownload serves one CA certificate ("<id>.crt") or all of them ("ca-bundle.pem") as PEM.
func (s *Server) certDownload(w http.ResponseWriter, r *http.Request) {
	if !s.settings.Bool("home_certs_enabled") {
		s.fail(w, r, http.StatusNotFound, "Certificate downloads are turned off.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	dir, dirErr := s.Dir()
	certs := s.caCerts(ctx, dir, dirErr)
	file := r.PathValue("file")
	var buf bytes.Buffer
	name := ""
	for _, c := range certs {
		if file == "ca-bundle.pem" || file == c.ID+".crt" {
			pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.der})
			if name = c.File; file == "ca-bundle.pem" {
				name = "ca-bundle.pem"
			}
		}
	}
	if buf.Len() == 0 {
		s.fail(w, r, http.StatusNotFound, "No such certificate.")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}
