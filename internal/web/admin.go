package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/settings"
)

type settingView struct {
	settings.Def
	Value  string
	Locked bool
	IsSet  bool
}

type sectionView struct {
	Name     string
	ID       string
	Settings []settingView
}

func sectionID(name string) string {
	id := strings.ToLower(name)
	return strings.NewReplacer(" ", "-", "(", "", ")", "").Replace(id)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "Administration", "admin")
	var sections []sectionView
	for _, name := range settings.Sections {
		sec := sectionView{Name: name, ID: sectionID(name)}
		for _, d := range settings.Defs {
			if d.Section != name {
				continue
			}
			v := settingView{Def: d, Locked: s.settings.Locked(d.Key), IsSet: s.settings.IsSet(d.Key)}
			if d.Kind != settings.Secret {
				v.Value = s.settings.Get(d.Key)
			}
			sec.Settings = append(sec.Settings, v)
		}
		sections = append(sections, sec)
	}
	p.Data["Sections"] = sections
	p.Data["Outbox"], _ = s.store.OutboxStats(r.Context())
	p.Data["OutboxError"], _ = s.store.LastOutboxError(r.Context())
	p.Data["Database"] = s.cfg.DatabaseKind
	p.Data["BaseURL"] = s.cfg.BaseURL
	p.Data["Callback"] = s.cfg.BaseURL + "/auth/callback"
	s.render(w, r, http.StatusOK, "admin", p)
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	section := r.PostFormValue("section")
	actor := sessionFrom(r).Username
	if actor == "" {
		actor = "(setup admin)"
	}
	var errs []string
	var changed []string
	for _, d := range settings.Defs {
		if d.Section != section || s.settings.Locked(d.Key) {
			continue
		}
		var v string
		switch d.Kind {
		case settings.Bool:
			v = "false"
			if r.PostFormValue(d.Key) != "" {
				v = "true"
			}
		case settings.Secret:
			if r.PostFormValue("clear_"+d.Key) != "" {
				v = ""
			} else if v = r.PostFormValue(d.Key); v == "" {
				continue // blank keeps the stored secret
			}
		case settings.TextArea:
			v = strings.TrimSpace(strings.ReplaceAll(r.PostFormValue(d.Key), "\r\n", "\n"))
		default:
			v = strings.TrimSpace(r.PostFormValue(d.Key))
		}
		if d.Kind != settings.Secret && v == s.settings.Get(d.Key) {
			continue
		}
		if err := s.settings.Set(r.Context(), d.Key, v, actor); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		changed = append(changed, d.Key)
	}
	if len(changed) > 0 {
		s.audit(r, "settings.changed", section, strings.Join(changed, ", ")) // names only, never values
	}
	to := "/admin#" + sectionID(section)
	if len(errs) > 0 {
		s.back(w, r, to, "Not saved: "+strings.Join(errs, "; "), true)
		return
	}
	s.back(w, r, to, section+" saved.", false)
}

func (s *Server) adminTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var err error
	var section, ok string
	switch r.PathValue("what") {
	case "ldap":
		section, ok = "Directory (LDAP)", "Connected and bound to the directory; user and group bases are readable."
		dir, derr := s.Dir()
		if err = derr; err == nil {
			err = dir.Ping(ctx)
		}
	case "oidc":
		section, ok = "Sign-in (OIDC)", "The issuer's discovery document loaded."
		err = s.oidc.Check(ctx)
	case "mail":
		section = "Notifications"
		to := strings.TrimSpace(r.PostFormValue("to"))
		if err = checkEmail(to); err == nil {
			ok = "Test message sent to " + to + "."
			err = s.notifier.SendNow(ctx, "test", to, nil)
		}
	default:
		s.fail(w, r, http.StatusNotFound, "Unknown test.")
		return
	}
	s.audit(r, "settings.test", r.PathValue("what"), errText(err))
	if err != nil {
		s.back(w, r, "/admin#"+sectionID(section), "Test failed: "+err.Error(), true)
		return
	}
	s.back(w, r, "/admin#"+sectionID(section), ok, false)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
