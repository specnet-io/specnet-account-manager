// Package auth is the OIDC sign-in (authorization code + PKCE). See DETAILS.md §Sign-in.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/specnet-io/specnet-account-manager/internal/settings"
)

// ErrNotConfigured means the issuer or client id is missing.
var ErrNotConfigured = errors.New("single sign-on is not configured yet")

// OIDC builds and caches the provider from current settings.
type OIDC struct {
	settings    *settings.Settings
	redirectURL string

	mu       sync.Mutex
	version  uint64
	provider *oidc.Provider
	issuer   string
}

// New returns an OIDC helper; redirectURL is <base>/auth/callback.
func New(s *settings.Settings, redirectURL string) *OIDC {
	return &OIDC{settings: s, redirectURL: redirectURL}
}

// Configured reports whether issuer and client id are set.
func (o *OIDC) Configured() bool {
	return o.settings.Get("oidc_issuer") != "" && o.settings.Get("oidc_client_id") != ""
}

func (o *OIDC) load(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	if !o.Configured() {
		return nil, nil, ErrNotConfigured
	}
	issuer := o.settings.Get("oidc_issuer")
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider == nil || o.version != o.settings.Version() || o.issuer != issuer {
		// Discovery is done on a background context: the provider keeps using it for JWKS refreshes.
		p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), nil), issuer)
		if err != nil {
			return nil, nil, fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
		}
		o.provider, o.version, o.issuer = p, o.settings.Version(), issuer
	}
	scopes := o.settings.List("oidc_scopes")
	hasOpenID := false
	for _, s := range scopes {
		if s == oidc.ScopeOpenID {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	cfg := &oauth2.Config{
		ClientID:     o.settings.Get("oidc_client_id"),
		ClientSecret: o.settings.Get("oidc_client_secret"),
		Endpoint:     o.provider.Endpoint(),
		RedirectURL:  o.redirectURL,
		Scopes:       scopes,
	}
	return o.provider, cfg, nil
}

// Check runs discovery (admin "test" button).
func (o *OIDC) Check(ctx context.Context) error {
	_, _, err := o.load(ctx)
	return err
}

// AuthCodeURL returns the provider URL to send the browser to.
func (o *OIDC) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	_, cfg, err := o.load(ctx)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Identity is what SAM takes from the ID token.
type Identity struct {
	Subject string
	Claim   string // value of the configured username claim
	Email   string
}

// Exchange redeems the code, verifies the ID token and nonce, and extracts the matching claim.
func (o *OIDC) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, error) {
	p, cfg, err := o.load(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("the provider returned no ID token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("ID token: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, errors.New("ID token nonce mismatch")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	id := &Identity{Subject: idt.Subject}
	if e, ok := claims["email"].(string); ok {
		id.Email = e
	}
	claimName := o.settings.Get("oidc_username_claim")
	v, _ := claims[claimName].(string)
	if v == "" {
		return nil, fmt.Errorf("the ID token has no %q claim (add the scope that provides it)", claimName)
	}
	if o.settings.Bool("oidc_strip_domain") {
		if i := strings.LastIndex(v, "@"); i > 0 {
			v = v[:i]
		}
	}
	id.Claim = v
	return id, nil
}
