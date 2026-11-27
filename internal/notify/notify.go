// Package notify renders event emails and delivers them through a sealed DB outbox (Mailjet API by default, or SMTP). See DETAILS.md §Notifications.
package notify

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"text/template"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

//go:embed templates/*.txt
var templateFS embed.FS

var templates = template.Must(template.New("").Option("missingkey=zero").ParseFS(templateFS, "templates/*.txt"))

// Message is one rendered email.
type Message struct {
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
	Event   string   `json:"event"`
}

// Sender delivers a message.
type Sender interface {
	Send(ctx context.Context, from Address, m Message) error
}

// Address is a sender identity.
type Address struct {
	Email string
	Name  string
}

// Notifier queues and delivers notifications.
type Notifier struct {
	store    *store.Store
	sealer   *secret.Sealer
	settings *settings.Settings
	baseURL  string
	log      *slog.Logger

	// SenderOverride replaces the provider chosen from settings (tests).
	SenderOverride Sender
	wake           chan struct{}
}

// New builds a Notifier.
func New(st *store.Store, sealer *secret.Sealer, s *settings.Settings, baseURL string, log *slog.Logger) *Notifier {
	return &Notifier{store: st, sealer: sealer, settings: s, baseURL: baseURL, log: log, wake: make(chan struct{}, 1)}
}

// Data is the template input; common fields are filled in by Notify.
type Data map[string]any

// Render produces a message for event without queuing it.
func (n *Notifier) Render(event string, to []string, data Data) (Message, error) {
	if data == nil {
		data = Data{}
	}
	data["Site"] = n.settings.Get("site_name")
	data["Support"] = n.settings.Get("support_email")
	data["BaseURL"] = n.baseURL
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, event+".txt", data); err != nil {
		return Message{}, fmt.Errorf("render %s: %w", event, err)
	}
	subject, body, ok := strings.Cut(buf.String(), "\n")
	if !ok || !strings.HasPrefix(subject, "Subject: ") {
		return Message{}, fmt.Errorf("template %s: first line must be 'Subject: ...'", event)
	}
	return Message{
		To:      to,
		Subject: strings.TrimSpace(strings.TrimPrefix(subject, "Subject: ")),
		Text:    strings.TrimLeft(body, "\n") + footer(n.settings),
		Event:   event,
	}, nil
}

func footer(s *settings.Settings) string {
	f := "\n-- \n" + s.Get("site_name") + "\n"
	if sup := s.Get("support_email"); sup != "" {
		f += "Questions? Contact " + sup + "\n"
	}
	return f
}

// Notify renders and queues a notification; it never fails the caller's action (errors are logged).
func (n *Notifier) Notify(ctx context.Context, event string, to []string, data Data) {
	var rcpt []string
	seen := map[string]bool{}
	for _, t := range to {
		t = strings.TrimSpace(t)
		if t != "" && !seen[strings.ToLower(t)] {
			seen[strings.ToLower(t)] = true
			rcpt = append(rcpt, t)
		}
	}
	if len(rcpt) == 0 || n.settings.Get("notify_provider") == "none" {
		return
	}
	m, err := n.Render(event, rcpt, data)
	if err != nil {
		n.log.Error("notification render failed", "event", event, "err", err)
		return
	}
	// One outbox row per recipient so one bad address doesn't block the rest.
	for _, r := range rcpt {
		one := m
		one.To = []string{r}
		b, _ := json.Marshal(one)
		if err := n.store.Enqueue(ctx, n.sealer.Seal(b, "outbox")); err != nil {
			n.log.Error("notification enqueue failed", "event", event, "err", err)
		}
	}
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// SendNow renders and delivers synchronously (admin "send test email").
func (n *Notifier) SendNow(ctx context.Context, event string, to string, data Data) error {
	m, err := n.Render(event, []string{to}, data)
	if err != nil {
		return err
	}
	sender, from, err := n.sender()
	if err != nil {
		return err
	}
	return sender.Send(ctx, from, m)
}

func (n *Notifier) sender() (Sender, Address, error) {
	from := Address{Email: n.settings.Get("mail_from_address"), Name: n.settings.Get("mail_from_name")}
	if from.Name == "" {
		from.Name = n.settings.Get("site_name")
	}
	if n.SenderOverride != nil {
		return n.SenderOverride, from, nil
	}
	provider := n.settings.Get("notify_provider")
	if provider != "log" && provider != "none" && from.Email == "" {
		return nil, from, errors.New("notifications: no From address configured")
	}
	switch provider {
	case "mailjet":
		return &Mailjet{
			URL:       n.settings.Get("mailjet_api_url"),
			APIKey:    n.settings.Get("mailjet_api_key"),
			APISecret: n.settings.Get("mailjet_api_secret"),
		}, from, nil
	case "smtp":
		return &SMTP{
			Host:     n.settings.Get("smtp_host"),
			Port:     n.settings.Int("smtp_port"),
			Security: n.settings.Get("smtp_security"),
			Username: n.settings.Get("smtp_username"),
			Password: n.settings.Get("smtp_password"),
		}, from, nil
	case "log":
		return logSender{n.log}, from, nil
	}
	return nil, from, errors.New("notifications are turned off")
}

const maxAttempts = 8

// Run delivers queued messages until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		n.deliverDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-n.wake:
		}
	}
}

// Flush delivers everything that is due now (tests and shutdown).
func (n *Notifier) Flush(ctx context.Context) { n.deliverDue(ctx) }

func (n *Notifier) deliverDue(ctx context.Context) {
	items, err := n.store.DueOutbox(ctx, 50)
	if err != nil {
		n.log.Error("outbox read failed", "err", err)
		return
	}
	if len(items) == 0 {
		return
	}
	sender, from, serr := n.sender()
	for _, it := range items {
		attempt := it.Attempts + 1
		fail := func(err error) {
			backoff := time.Duration(1<<min(attempt, 10)) * 30 * time.Second
			n.log.Warn("notification delivery failed", "id", it.ID, "attempt", attempt, "err", err)
			if e := n.store.MarkFailed(ctx, it.ID, attempt, maxAttempts, time.Now().Add(backoff), err.Error()); e != nil {
				n.log.Error("outbox update failed", "err", e)
			}
		}
		if serr != nil {
			fail(serr)
			continue
		}
		raw, err := n.sealer.Open(it.Payload, "outbox")
		if err != nil {
			fail(err)
			continue
		}
		var m Message
		if err := json.Unmarshal(raw, &m); err != nil {
			fail(err)
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = sender.Send(sctx, from, m)
		cancel()
		if err != nil {
			fail(err)
			continue
		}
		if err := n.store.MarkSent(ctx, it.ID); err != nil {
			n.log.Error("outbox update failed", "err", err)
		}
		n.log.Info("notification sent", "event", m.Event)
	}
}

type logSender struct{ log *slog.Logger }

// Send logs only the event and subject: bodies may contain one-time links.
func (l logSender) Send(_ context.Context, _ Address, m Message) error {
	l.log.Info("notification (log delivery)", "event", m.Event, "subject", m.Subject, "recipients", len(m.To))
	return nil
}
