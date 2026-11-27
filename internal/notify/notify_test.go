package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

func setup(t *testing.T) (*Notifier, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealer, _ := secret.NewSealer(make([]byte, 32))
	s, err := settings.Load(context.Background(), st, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return New(st, sealer, s, "https://sam.test", slog.New(slog.NewTextHandler(io.Discard, nil))), st
}

func TestAllTemplatesRender(t *testing.T) {
	n, _ := setup(t)
	count := 0
	for _, tpl := range templates.Templates() {
		name := strings.TrimSuffix(tpl.Name(), ".txt")
		if name == "" || name == tpl.Name() {
			continue
		}
		count++
		m, err := n.Render(name, []string{"a@b.test"}, Data{"Name": "N", "Link": "https://x/y?t=1", "Username": "u", "Hours": 1, "Note": "n",
			"NewEmail": "e@x.test", "Group": "g", "Requester": "r", "Description": "d", "Justification": "j", "Email": "e@x.test",
			"KeyType": "ssh-ed25519", "Fingerprint": "SHA256:x", "Comment": "c", "By": "m", "Owners": "o", "Approved": true, "Added": true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if m.Subject == "" || strings.Contains(m.Text, "<no value>") {
			t.Fatalf("%s rendered badly: %q / %q", name, m.Subject, m.Text)
		}
	}
	if count < 15 {
		t.Fatalf("only %d templates found", count)
	}
}

func TestMailjetOutbox(t *testing.T) {
	var got []map[string]any
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "key" || p != "sec" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		if fail {
			fail = false
			http.Error(w, `{"ErrorMessage":"busy"}`, http.StatusServiceUnavailable)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		_, _ = w.Write([]byte(`{"Messages":[{"Status":"success"}]}`))
	}))
	defer srv.Close()
	n, st := setup(t)
	ctx := context.Background()
	for k, v := range map[string]string{"mailjet_api_url": srv.URL, "mailjet_api_key": "key", "mailjet_api_secret": "sec", "mail_from_address": "noreply@sam.test"} {
		if err := n.settings.Set(ctx, k, v, "t"); err != nil {
			t.Fatal(err)
		}
	}
	n.Notify(ctx, "password_reset", []string{"u@x.test", "U@x.test"}, Data{"Name": "U", "Username": "u", "Link": "https://sam.test/reset-password?t=SECRET", "Hours": 1})
	raw, _ := st.DueOutbox(ctx, 10)
	if len(raw) != 1 {
		t.Fatalf("dedupe: %d rows", len(raw))
	}
	if strings.Contains(raw[0].Payload, "SECRET") || !secret.IsSealed(raw[0].Payload) {
		t.Fatal("outbox payload not sealed")
	}
	n.Flush(ctx) // first attempt fails -> backoff
	if len(got) != 0 {
		t.Fatal("sent despite failure")
	}
	if stats, _ := st.OutboxStats(ctx); stats["queued"] != 1 {
		t.Fatalf("stats: %v", stats)
	}
	if err := st.MarkFailed(ctx, raw[0].ID, 1, 8, time.Unix(0, 0), "x"); err != nil { // due again
		t.Fatal(err)
	}
	n.Flush(ctx)
	if len(got) != 1 {
		t.Fatalf("not delivered: %v", got)
	}
	msg := got[0]["Messages"].([]any)[0].(map[string]any)
	if msg["Subject"] == "" || !strings.Contains(msg["TextPart"].(string), "reset-password?t=SECRET") {
		t.Fatalf("payload: %v", msg)
	}
	if stats, _ := st.OutboxStats(ctx); stats["sent"] != 1 {
		t.Fatalf("stats after send: %v", stats)
	}
}

func TestProviderNone(t *testing.T) {
	n, st := setup(t)
	ctx := context.Background()
	if err := n.settings.Set(ctx, "notify_provider", "none", "t"); err != nil {
		t.Fatal(err)
	}
	n.Notify(ctx, "test", []string{"a@b.test"}, nil)
	if due, _ := st.DueOutbox(ctx, 10); len(due) != 0 {
		t.Fatal("queued while notifications are off")
	}
}

func TestMIMEHeadersSafe(t *testing.T) {
	b := string(buildMIME(Address{Email: "a@b.test", Name: "Site"}, Message{To: []string{"x@y.test"}, Subject: "Hi\r\nBcc: evil@x.test", Text: "body"}))
	if strings.Contains(b, "\r\nBcc:") {
		t.Fatal("header injection")
	}
}
