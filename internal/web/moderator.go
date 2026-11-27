package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

func (s *Server) modHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/mod/accounts", http.StatusSeeOther)
}

func (s *Server) modAccounts(w http.ResponseWriter, r *http.Request) {
	pending, err := s.store.ListAccountRequests(r.Context(), store.StatusPending, 200)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Requests could not be loaded.")
		return
	}
	recent, _ := s.store.ListAccountRequests(r.Context(), "", 50)
	p := s.page(w, r, "Account requests", "mod")
	p.Data["Pending"] = pending
	p.Data["Recent"] = recent
	s.render(w, r, http.StatusOK, "mod_accounts", p)
}

func (s *Server) decideAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	se := sessionFrom(r)
	req, err := s.store.GetAccountRequest(ctx, r.PathValue("id"))
	if err != nil || req.Status != store.StatusPending {
		s.back(w, r, "/mod/accounts", "That request is no longer pending.", true)
		return
	}
	note := cleanText(r.PostFormValue("note"), 1000)
	dir, err := s.Dir()
	if err != nil {
		s.back(w, r, "/mod/accounts", "The directory is not configured.", true)
		return
	}
	if r.PostFormValue("decision") != "approve" {
		if err := s.store.SetAccountRequestStatus(ctx, req.ID, store.StatusPending, store.StatusDenied, se.Username, note); err != nil {
			s.back(w, r, "/mod/accounts", "That request is no longer pending.", true)
			return
		}
		s.audit(r, "account_request.denied", req.Username, note)
		s.notifier.Notify(ctx, "account_denied", []string{req.Email}, notify.Data{"Name": req.GivenName, "Username": req.Username, "Note": note})
		s.back(w, r, "/mod/accounts", "Request for "+req.Username+" denied.", false)
		return
	}
	// Claim the request first so two moderators can't both create the account.
	if err := s.store.SetAccountRequestStatus(ctx, req.ID, store.StatusPending, store.StatusApproved, se.Username, note); err != nil {
		s.back(w, r, "/mod/accounts", "That request is no longer pending.", true)
		return
	}
	err = dir.CreateUser(ctx, directory.NewUser{Username: req.Username, GivenName: req.GivenName, Surname: req.Surname, Email: req.Email})
	if err != nil {
		_ = s.store.SetAccountRequestStatus(ctx, req.ID, store.StatusApproved, store.StatusPending, "", "")
		s.log.Error("create user", "user", req.Username, "err", err)
		msg := "The account could not be created: " + userFacing(err)
		if errors.Is(err, directory.ErrExists) {
			msg = "An account named " + req.Username + " already exists. Deny this request with a note."
		}
		s.back(w, r, "/mod/accounts", msg, true)
		return
	}
	s.audit(r, "account_request.approved", req.Username, note)
	u, err := dir.GetUser(ctx, req.Username)
	if err != nil {
		s.back(w, r, "/mod/accounts", "The account was created but could not be read back; send the user a reset link from Users.", true)
		return
	}
	s.sendPasswordLink(r, u, "account_approved", setupTTL, nil)
	s.back(w, r, "/mod/accounts", "Account "+req.Username+" created. The user was emailed a link to set a password.", false)
}

func (s *Server) modGroupRequests(w http.ResponseWriter, r *http.Request) {
	pending, err := s.store.ListGroupRequests(r.Context(), store.StatusPending, "", 200)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Requests could not be loaded.")
		return
	}
	recent, _ := s.store.ListGroupRequests(r.Context(), "", "", 50)
	p := s.page(w, r, "Group requests", "mod")
	p.Data["Pending"] = pending
	p.Data["Recent"] = recent
	s.render(w, r, http.StatusOK, "mod_group_requests", p)
}

func (s *Server) decideGroupRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	se := sessionFrom(r)
	req, err := s.store.GetGroupRequest(ctx, r.PathValue("id"))
	if err != nil || req.Status != store.StatusPending {
		s.back(w, r, "/mod/group-requests", "That request is no longer pending.", true)
		return
	}
	note := cleanText(r.PostFormValue("note"), 1000)
	dir, err := s.Dir()
	if err != nil {
		s.back(w, r, "/mod/group-requests", "The directory is not configured.", true)
		return
	}
	requester, rerr := dir.GetUser(ctx, req.Requester)
	if r.PostFormValue("decision") != "approve" {
		if err := s.store.SetGroupRequestStatus(ctx, req.ID, store.StatusPending, store.StatusDenied, se.Username, note); err != nil {
			s.back(w, r, "/mod/group-requests", "That request is no longer pending.", true)
			return
		}
		s.audit(r, "group_request.denied", req.Name, note)
		if rerr == nil {
			s.notifier.Notify(ctx, "group_request_denied", []string{requester.Email}, notify.Data{"Name": requester.Name(), "Group": req.Name, "Note": note})
		}
		s.back(w, r, "/mod/group-requests", "Request for "+req.Name+" denied.", false)
		return
	}
	if rerr != nil {
		s.back(w, r, "/mod/group-requests", "The requester's account no longer exists; deny the request instead.", true)
		return
	}
	if s.reserved(req.Name) {
		s.back(w, r, "/mod/group-requests", "That group name is reserved.", true)
		return
	}
	if err := s.store.SetGroupRequestStatus(ctx, req.ID, store.StatusPending, store.StatusApproved, se.Username, note); err != nil {
		s.back(w, r, "/mod/group-requests", "That request is no longer pending.", true)
		return
	}
	if err := dir.CreateGroup(ctx, req.Name, req.Description, req.Requester); err != nil {
		_ = s.store.SetGroupRequestStatus(ctx, req.ID, store.StatusApproved, store.StatusPending, "", "")
		s.log.Error("create group", "group", req.Name, "err", err)
		s.back(w, r, "/mod/group-requests", "The group could not be created: "+userFacing(err), true)
		return
	}
	if err := s.store.AddManagedGroup(ctx, req.Name, se.Username, req.Requester); err != nil {
		s.back(w, r, "/mod/group-requests", "The group was created but could not be registered here. Adopt it from Groups.", true)
		return
	}
	s.audit(r, "group_request.approved", req.Name, "owner: "+req.Requester)
	s.notifier.Notify(ctx, "group_request_approved", []string{requester.Email}, notify.Data{"Name": requester.Name(), "Group": req.Name, "Link": s.link(s.groupPath(req.Name), nil)})
	s.back(w, r, "/mod/group-requests", "Group "+req.Name+" created, owned by "+req.Requester+".", false)
}

func (s *Server) modGroups(w http.ResponseWriter, r *http.Request) {
	managed, err := s.store.ListManagedGroups(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Groups could not be loaded.")
		return
	}
	p := s.page(w, r, "Managed groups", "mod")
	p.Data["Managed"] = managed
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	p.Data["Query"] = q
	if q != "" {
		if dir, err := s.Dir(); err == nil {
			found, err := dir.SearchGroups(r.Context(), q, 50)
			if err != nil {
				p.Error = "Directory search failed."
			}
			isManaged := map[string]bool{}
			for _, g := range managed {
				isManaged[strings.ToLower(g.Name)] = true
			}
			var rows []groupRow
			for _, g := range found {
				rows = append(rows, groupRow{Name: g.Name, Description: g.Description, Managed: isManaged[strings.ToLower(g.Name)] || !s.manageable(g)})
			}
			p.Data["Found"] = rows
		}
	}
	s.render(w, r, http.StatusOK, "mod_groups", p)
}

func (s *Server) adoptGroup(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	owner := strings.ToLower(strings.TrimSpace(r.PostFormValue("owner")))
	dir, err := s.Dir()
	if err != nil {
		s.back(w, r, "/mod/groups", "The directory is not configured.", true)
		return
	}
	g, err := dir.GetGroup(r.Context(), name)
	if err != nil {
		s.back(w, r, "/mod/groups", "No directory group named "+name+".", true)
		return
	}
	if !s.manageable(g) {
		s.back(w, r, "/mod/groups", s.notManageableMsg(g), true)
		return
	}
	if owner != "" {
		if _, err := dir.GetUser(r.Context(), owner); err != nil {
			s.back(w, r, "/mod/groups", "No account named "+owner+".", true)
			return
		}
	}
	if err := s.store.AddManagedGroup(r.Context(), g.Name, sessionFrom(r).Username, owner); err != nil {
		s.back(w, r, "/mod/groups", "Something went wrong. Try again.", true)
		return
	}
	s.audit(r, "group.adopted", g.Name, "owner: "+owner)
	s.back(w, r, s.groupPath(g.Name), g.Name+" is now managed here.", false)
}

func (s *Server) modUsers(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "Users", "mod")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	p.Data["Query"] = q
	if q != "" {
		dir, err := s.Dir()
		if err != nil {
			p.Error = "The directory is not configured."
		} else if users, err := dir.SearchUsers(r.Context(), q, 50); err != nil {
			p.Error = "Directory search failed."
		} else {
			p.Data["Users"] = users
		}
	}
	s.render(w, r, http.StatusOK, "mod_users", p)
}

func (s *Server) modUser(w http.ResponseWriter, r *http.Request) {
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return
	}
	u, err := dir.GetUser(r.Context(), r.PathValue("username"))
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such account.")
		return
	}
	groups, _ := dir.UserGroups(r.Context(), u.Username)
	owned, _ := s.store.OwnedGroups(r.Context(), u.Username)
	var keys []*directory.SSHKey
	for _, k := range u.SSHKeys {
		keys = append(keys, directory.DescribeSSHKey(k))
	}
	p := s.page(w, r, u.Username, "mod")
	p.Data["User"] = u
	p.Data["Groups"] = groups
	p.Data["Owned"] = owned
	p.Data["Keys"] = keys
	s.render(w, r, http.StatusOK, "mod_user", p)
}

func (s *Server) forceReset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("username")
	back := "/mod/users/" + name
	dir, err := s.Dir()
	if err != nil {
		s.back(w, r, back, "The directory is not configured.", true)
		return
	}
	u, err := dir.GetUser(r.Context(), name)
	if err != nil {
		s.back(w, r, back, "No such account.", true)
		return
	}
	if err := dir.ExpirePassword(r.Context(), u.Username); err != nil {
		s.log.Error("force reset", "user", u.Username, "err", err)
		s.back(w, r, back, "The password could not be reset: "+userFacing(err), true)
		return
	}
	_ = s.store.DeleteUserSessions(r.Context(), u.Username)
	note := cleanText(r.PostFormValue("note"), 1000)
	if u.Email != "" {
		s.sendPasswordLink(r, u, "password_forced", setupTTL, map[string]any{"Note": note})
	}
	s.audit(r, "password.forced_reset", u.Username, note)
	msg := "Password reset. " + u.Username + " was emailed a link to choose a new one."
	if u.Email == "" {
		msg = "Password reset, but the account has no email address: the user cannot set a new password themselves."
	}
	s.back(w, r, back, msg, u.Email == "")
}

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	entries, err := s.store.ListAudit(r.Context(), q, 300)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "The activity log could not be loaded.")
		return
	}
	p := s.page(w, r, "Activity", "activity")
	p.Data["Entries"] = entries
	p.Data["Query"] = q
	s.render(w, r, http.StatusOK, "activity", p)
}
