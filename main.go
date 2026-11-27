// Command sam is the specnet-account-manager server. See README.md and DETAILS.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
	"github.com/specnet-io/specnet-account-manager/internal/store"
	"github.com/specnet-io/specnet-account-manager/internal/web"
)

var version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "admin-link":
		err = adminLink(os.Args[2:])
	case "gen-key":
		fmt.Println(secret.NewKey())
	case "healthcheck":
		err = healthcheck()
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sam:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: sam [command]

  serve        run the web server (default)
  admin-link   print a one-time setup sign-in link for the admin page (-ttl 15m)
  gen-key      print a new SAM_ENCRYPTION_KEY
  healthcheck  exit 0 if the local server answers /healthz
  version      print the version
`)
}

// env holds the environment-only settings. See DETAILS.md §Environment.
type env struct {
	listen   string
	database string
	baseURL  string
	proxies  []netip.Prefix
	sealer   *secret.Sealer
	logLevel slog.Level
}

func loadEnv() (*env, error) {
	e := &env{listen: ":8080"}
	get := func(name string) (string, error) {
		v, _, err := settings.Env(name)
		return strings.TrimSpace(v), err
	}
	var err error
	if v, err := get("SAM_LISTEN"); err != nil {
		return nil, err
	} else if v != "" {
		e.listen = v
	}
	dataDir, err := get("SAM_DATA_DIR")
	if err != nil {
		return nil, err
	}
	if dataDir == "" {
		dataDir = "./data"
	}
	if e.database, err = get("SAM_DATABASE_URL"); err != nil {
		return nil, err
	}
	if e.database == "" {
		e.database = "sqlite://" + strings.TrimRight(dataDir, "/") + "/sam.db"
	}
	if e.baseURL, err = get("SAM_BASE_URL"); err != nil {
		return nil, err
	}
	if e.baseURL == "" {
		return nil, errors.New("SAM_BASE_URL is required (the public https URL users reach this site on)")
	}
	key, err := get("SAM_ENCRYPTION_KEY")
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("SAM_ENCRYPTION_KEY (or SAM_ENCRYPTION_KEY_FILE) is required; create one with: sam gen-key")
	}
	raw, err := secret.ParseKey(key)
	if err != nil {
		return nil, fmt.Errorf("SAM_ENCRYPTION_KEY: %w", err)
	}
	if e.sealer, err = secret.NewSealer(raw); err != nil {
		return nil, err
	}
	proxies, err := get("SAM_TRUSTED_PROXIES")
	if err != nil {
		return nil, err
	}
	for _, p := range settings.SplitList(proxies) {
		if !strings.Contains(p, "/") {
			if a, err := netip.ParseAddr(p); err == nil {
				p = netip.PrefixFrom(a, a.BitLen()).String()
			}
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("SAM_TRUSTED_PROXIES: %q is not an address or CIDR", p)
		}
		e.proxies = append(e.proxies, pfx.Masked())
	}
	lvl, _ := get("SAM_LOG_LEVEL")
	if lvl != "" {
		if err := e.logLevel.UnmarshalText([]byte(lvl)); err != nil {
			return nil, fmt.Errorf("SAM_LOG_LEVEL: %w", err)
		}
	}
	return e, nil
}

func dbKind(url string) string {
	if strings.HasPrefix(url, "postgres") {
		return "PostgreSQL"
	}
	return "SQLite"
}

func serve() error {
	e, err := loadEnv()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: e.logLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, e.database)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := settings.Load(ctx, st, e.sealer)
	if err != nil {
		return err
	}
	n := notify.New(st, e.sealer, s, strings.TrimRight(e.baseURL, "/"), log)
	srv, err := web.New(web.Config{BaseURL: e.baseURL, TrustedProxies: e.proxies, Version: version, DatabaseKind: dbKind(e.database)}, st, s, e.sealer, n, log)
	if err != nil {
		return err
	}
	go n.Run(ctx)
	go housekeeping(ctx, st, s, log)

	hs := &http.Server{
		Addr:              e.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("sam started", "version", version, "listen", e.listen, "base_url", e.baseURL, "database", dbKind(e.database))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

func housekeeping(ctx context.Context, st *store.Store, s *settings.Settings, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := st.ExpireUnverifiedRequests(ctx, 48*time.Hour); err != nil {
			log.Warn("expire requests", "err", err)
		} else if n > 0 {
			log.Info("expired unconfirmed account requests", "count", n)
		}
		if err := st.Cleanup(ctx, time.Duration(s.Int("audit_retention_days"))*24*time.Hour); err != nil {
			log.Warn("cleanup", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// adminLink prints a one-time setup link (token stored hashed). See DETAILS.md §Bootstrap.
func adminLink(args []string) error {
	fs := flag.NewFlagSet("admin-link", flag.ContinueOnError)
	ttl := fs.Duration("ttl", 15*time.Minute, "how long the link works")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ttl <= 0 || *ttl > 24*time.Hour {
		return errors.New("-ttl must be between 1s and 24h")
	}
	e, err := loadEnv()
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, e.database)
	if err != nil {
		return err
	}
	defer st.Close()
	tok := secret.Token()
	if err := st.PutToken(ctx, &store.Token{Hash: secret.Hash(tok), Purpose: store.PurposeAdminLink, Subject: "bootstrap", ExpiresAt: time.Now().Add(*ttl)}, false); err != nil {
		return err
	}
	_ = st.Audit(ctx, "(cli)", "admin_link.created", "", "valid for "+ttl.String(), "local")
	fmt.Println(strings.TrimRight(e.baseURL, "/") + "/admin-link?t=" + url.QueryEscape(tok))
	return nil
}

func healthcheck() error {
	listen := ":8080"
	if v, _, _ := settings.Env("SAM_LISTEN"); v != "" {
		listen = v
	}
	host := listen
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://" + host + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
