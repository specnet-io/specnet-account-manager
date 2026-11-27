package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Mailjet sends through the Mailjet Send API v3.1.
type Mailjet struct {
	URL       string
	APIKey    string
	APISecret string
	Client    *http.Client
}

// Send posts one message.
func (m *Mailjet) Send(ctx context.Context, from Address, msg Message) error {
	if m.APIKey == "" || m.APISecret == "" {
		return errors.New("mailjet: API key and secret are not configured")
	}
	type addr struct {
		Email string `json:"Email"`
		Name  string `json:"Name,omitempty"`
	}
	to := make([]addr, 0, len(msg.To))
	for _, t := range msg.To {
		to = append(to, addr{Email: t})
	}
	body, _ := json.Marshal(map[string]any{"Messages": []map[string]any{{
		"From":     addr{Email: from.Email, Name: from.Name},
		"To":       to,
		"Subject":  msg.Subject,
		"TextPart": msg.Text,
		"CustomID": msg.Event,
	}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(m.APIKey, m.APISecret)
	req.Header.Set("Content-Type", "application/json")
	c := m.Client
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("mailjet: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("mailjet: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var parsed struct {
		Messages []struct {
			Status string `json:"Status"`
			Errors []struct {
				ErrorMessage string `json:"ErrorMessage"`
			} `json:"Errors"`
		} `json:"Messages"`
	}
	if json.Unmarshal(rb, &parsed) == nil {
		for _, pm := range parsed.Messages {
			if pm.Status != "" && pm.Status != "success" {
				var errs []string
				for _, e := range pm.Errors {
					errs = append(errs, e.ErrorMessage)
				}
				return fmt.Errorf("mailjet: %s: %s", pm.Status, strings.Join(errs, "; "))
			}
		}
	}
	return nil
}

// SMTP sends through an SMTP relay.
type SMTP struct {
	Host     string
	Port     int
	Security string // starttls | tls | none
	Username string
	Password string
}

// Send delivers one message.
func (s *SMTP) Send(ctx context.Context, from Address, msg Message) error {
	if s.Host == "" {
		return errors.New("smtp: host is not configured")
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	d := &net.Dialer{Timeout: 15 * time.Second}
	tc := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if s.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tc}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if s.Security == "starttls" {
		if err := c.StartTLS(tc); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}
	if s.Username != "" {
		if s.Security == "none" {
			return errors.New("smtp: refusing to send credentials without TLS")
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from.Email); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, t := range msg.To {
		if err := c.Rcpt(t); err != nil {
			return fmt.Errorf("smtp RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(buildMIME(from, msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return c.Quit()
}

func buildMIME(from Address, msg Message) []byte {
	var b bytes.Buffer
	fromHdr := from.Email
	if from.Name != "" {
		fromHdr = mime.QEncoding.Encode("utf-8", from.Name) + " <" + from.Email + ">"
	}
	hdr := func(k, v string) {
		b.WriteString(k + ": " + strings.NewReplacer("\r", "", "\n", "").Replace(v) + "\r\n")
	}
	hdr("From", fromHdr)
	hdr("To", strings.Join(msg.To, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	for _, line := range strings.Split(strings.ReplaceAll(msg.Text, "\r\n", "\n"), "\n") {
		b.WriteString(line + "\r\n") // net/smtp's DATA writer does the dot-stuffing
	}
	return b.Bytes()
}
