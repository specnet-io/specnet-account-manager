package web

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

type groupRow struct {
	Name        string
	Description string
	Owners      []string
	Managed     bool
	Member      bool
	Owner       bool
	Pending     bool
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return
	}
	ctx := r.Context()
	mine, err := dir.UserGroups(ctx, se.Username)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, "Your groups could not be loaded from the directory.")
		return
	}
	member := map[string]bool{}
	for _, g := range mine {
		member[strings.ToLower(g)] = true
	}
	managed, err := s.store.ListManagedGroups(ctx)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Groups could not be loaded.")
		return
	}
	joins, _ := s.store.ListJoinRequests(ctx, "", se.Username, "")
	pending := map[string]bool{}
	for _, j := range joins {
		if j.Status == store.StatusPending {
			pending[j.GroupName] = true
		}
	}
	// With ldap_fas_groups, a managed group whose FAS object class was removed drops out of the list.
	var fas map[string]bool
	if s.fasOnly() {
		found, err := dir.SearchGroups(ctx, "", 10000)
		if err != nil {
			s.fail(w, r, http.StatusBadGateway, "Groups could not be loaded from the directory.")
			return
		}
		fas = map[string]bool{}
		for _, g := range found {
			fas[strings.ToLower(g.Name)] = true
		}
	}
	isManaged := map[string]bool{}
	var browse []groupRow
	for _, g := range managed {
		if s.reserved(g.Name) || (fas != nil && !fas[strings.ToLower(g.Name)]) {
			continue
		}
		isManaged[strings.ToLower(g.Name)] = true
		browse = append(browse, groupRow{Name: g.Name, Owners: g.Owners, Managed: true, Member: member[strings.ToLower(g.Name)],
			Owner: has(g.Owners, se.Username), Pending: pending[g.Name]})
	}
	var memberOf []groupRow
	for _, g := range mine {
		memberOf = append(memberOf, groupRow{Name: g, Managed: isManaged[strings.ToLower(g)], Member: true})
	}
	greqs, _ := s.store.ListGroupRequests(ctx, "", se.Username, 50)
	p := s.page(w, r, "Groups", "groups")
	p.Data["MemberOf"] = memberOf
	p.Data["Browse"] = browse
	p.Data["Joins"] = joins
	p.Data["GroupRequests"] = greqs
	s.render(w, r, http.StatusOK, "groups", p)
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// managedCtx is a managed group as seen by the current user.
type managedCtx struct {
	dir     directory.Directory
	group   *directory.Group // nil if missing from the directory
	mg      *store.ManagedGroup
	isOwner bool
	isMod   bool
}

func (m *managedCtx) canManage() bool { return m.isOwner || m.isMod }

func (s *Server) loadManaged(w http.ResponseWriter, r *http.Request) (*managedCtx, bool) {
	name := r.PathValue("name")
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return nil, false
	}
	mg, err := s.store.GetManagedGroup(r.Context(), name)
	if err != nil || s.reserved(name) {
		s.fail(w, r, http.StatusNotFound, "That group is not managed here.")
		return nil, false
	}
	se := sessionFrom(r)
	m := &managedCtx{dir: dir, mg: mg, isOwner: has(mg.Owners, se.Username), isMod: se.HasRole(RoleModerator)}
	m.group, err = dir.GetGroup(r.Context(), name)
	if err != nil && !errors.Is(err, directory.ErrNotFound) {
		s.fail(w, r, http.StatusBadGateway, "The group could not be loaded from the directory.")
		return nil, false
	}
	if err != nil {
		m.group = nil
	}
	if m.group != nil && !s.manageable(m.group) {
		s.fail(w, r, http.StatusNotFound, "That group is not managed here.")
		return nil, false
	}
	return m, true
}

func (s *Server) group(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	se := sessionFrom(r)
	p := s.page(w, r, "Group "+m.mg.Name, "groups")
	p.Data["Name"] = m.mg.Name
	p.Data["Managed"] = m.mg
	p.Data["Group"] = m.group
	p.Data["CanManage"] = m.canManage()
	p.Data["IsMod"] = m.isMod
	if m.group != nil {
		p.Data["IsMember"] = has(m.group.Members, se.Username)
	}
	if m.canManage() {
		jr, _ := s.store.ListJoinRequests(r.Context(), m.mg.Name, "", store.StatusPending)
		p.Data["JoinRequests"] = jr
	} else {
		mine, _ := s.store.ListJoinRequests(r.Context(), m.mg.Name, se.Username, store.StatusPending)
		p.Data["Pending"] = len(mine) > 0
	}
	s.render(w, r, http.StatusOK, "group", p)
}

func (s *Server) groupPath(name string) string { return "/groups/" + url.PathEscape(name) }

func (s *Server) joinGroup(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	se := sessionFrom(r)
	back := s.groupPath(m.mg.Name)
	if m.group == nil {
		s.back(w, r, back, "This group no longer exists in the directory.", true)
		return
	}
	if has(m.group.Members, se.Username) {
		s.back(w, r, back, "You are already a member.", true)
		return
	}
	existing, _ := s.store.ListJoinRequests(r.Context(), m.mg.Name, se.Username, store.StatusPending)
	if len(existing) > 0 {
		s.back(w, r, back, "Your request is already waiting.", true)
		return
	}
	jr := &store.JoinRequest{GroupName: m.mg.Name, Username: se.Username, Note: cleanText(r.PostFormValue("note"), 500), Status: store.StatusPending}
	if err := s.store.CreateJoinRequest(r.Context(), jr); err != nil {
		s.back(w, r, back, "Something went wrong. Try again.", true)
		return
	}
	s.audit(r, "group.join_requested", m.mg.Name, "")
	to := s.emailsOf(r.Context(), m.dir, m.mg.Owners)
	if len(to) == 0 {
		to = s.moderatorEmails(r.Context(), m.dir)
	}
	s.notifier.Notify(r.Context(), "join_request", to, notify.Data{"Group": m.mg.Name, "Requester": se.Username, "Note": jr.Note, "Link": s.link(back, nil)})
	s.back(w, r, back, "Request sent to the group's owners.", false)
}

func (s *Server) leaveGroup(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	se := sessionFrom(r)
	if err := m.dir.RemoveMember(r.Context(), m.mg.Name, se.Username); err != nil {
		s.back(w, r, s.groupPath(m.mg.Name), userFacingGroup(err), true)
		return
	}
	s.audit(r, "group.left", m.mg.Name, se.Username)
	s.back(w, r, "/groups", "You left "+m.mg.Name+".", false)
}

// groupMembers adds or removes a member (owners and moderators).
func (s *Server) groupMembers(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	back := s.groupPath(m.mg.Name)
	if !m.canManage() {
		s.fail(w, r, http.StatusForbidden, "Only the group's owners and moderators can change its members.")
		return
	}
	if m.group == nil {
		s.back(w, r, back, "This group no longer exists in the directory.", true)
		return
	}
	user := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	u, err := m.dir.GetUser(r.Context(), user)
	if err != nil {
		s.back(w, r, back, "No account named "+user+".", true)
		return
	}
	se := sessionFrom(r)
	add := r.PostFormValue("action") == "add"
	if add {
		err = m.dir.AddMember(r.Context(), m.mg.Name, u.Username)
	} else {
		err = m.dir.RemoveMember(r.Context(), m.mg.Name, u.Username)
	}
	if err != nil {
		s.back(w, r, back, userFacingGroup(err), true)
		return
	}
	action := "group.member_removed"
	if add {
		action = "group.member_added"
		// Adding someone settles their pending request, if any.
		if jr, _ := s.store.ListJoinRequests(r.Context(), m.mg.Name, u.Username, store.StatusPending); len(jr) > 0 {
			for _, j := range jr {
				_ = s.store.SetJoinRequestStatus(r.Context(), j.ID, store.StatusPending, store.StatusApproved, se.Username)
			}
		}
	}
	s.audit(r, action, m.mg.Name, u.Username)
	if u.Username != se.Username {
		s.notifier.Notify(r.Context(), "membership_changed", []string{u.Email}, notify.Data{"Name": u.Name(), "Group": m.mg.Name, "By": se.Username, "Added": add})
	}
	if add {
		s.back(w, r, back, u.Username+" added.", false)
	} else {
		s.back(w, r, back, u.Username+" removed.", false)
	}
}

func (s *Server) decideJoin(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	back := s.groupPath(m.mg.Name)
	if !m.canManage() {
		s.fail(w, r, http.StatusForbidden, "Only the group's owners and moderators can decide join requests.")
		return
	}
	jr, err := s.store.GetJoinRequest(r.Context(), r.PathValue("id"))
	if err != nil || jr.GroupName != m.mg.Name || jr.Status != store.StatusPending {
		s.back(w, r, back, "That request is no longer waiting.", true)
		return
	}
	se := sessionFrom(r)
	approve := r.PostFormValue("decision") == "approve"
	if approve {
		if m.group == nil {
			s.back(w, r, back, "This group no longer exists in the directory.", true)
			return
		}
		if err := m.dir.AddMember(r.Context(), m.mg.Name, jr.Username); err != nil {
			s.back(w, r, back, userFacingGroup(err), true)
			return
		}
	}
	status := store.StatusDenied
	if approve {
		status = store.StatusApproved
	}
	if err := s.store.SetJoinRequestStatus(r.Context(), jr.ID, store.StatusPending, status, se.Username); err != nil {
		s.back(w, r, back, "That request is no longer waiting.", true)
		return
	}
	s.audit(r, "group.join_"+status, m.mg.Name, jr.Username)
	if u, err := m.dir.GetUser(r.Context(), jr.Username); err == nil {
		s.notifier.Notify(r.Context(), "join_decided", []string{u.Email}, notify.Data{"Name": u.Name(), "Group": m.mg.Name, "Approved": approve})
	}
	s.back(w, r, back, "Request "+status+".", false)
}

func (s *Server) groupDescription(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	back := s.groupPath(m.mg.Name)
	if !m.canManage() {
		s.fail(w, r, http.StatusForbidden, "Only the group's owners and moderators can change it.")
		return
	}
	d := clean(r.PostFormValue("description"), 256)
	if err := m.dir.SetGroupDescription(r.Context(), m.mg.Name, d); err != nil {
		s.back(w, r, back, userFacingGroup(err), true)
		return
	}
	s.audit(r, "group.description", m.mg.Name, d)
	s.back(w, r, back, "Description saved.", false)
}

// groupOwners adds, removes or transfers ownership (moderators).
func (s *Server) groupOwners(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	back := s.groupPath(m.mg.Name)
	user := strings.ToLower(strings.TrimSpace(r.PostFormValue("username")))
	u, err := m.dir.GetUser(r.Context(), user)
	if err != nil {
		s.back(w, r, back, "No account named "+user+".", true)
		return
	}
	ctx := r.Context()
	action := r.PostFormValue("action")
	switch action {
	case "add":
		err = s.store.AddOwner(ctx, m.mg.Name, u.Username)
	case "remove":
		err = s.store.RemoveOwner(ctx, m.mg.Name, u.Username)
	case "transfer":
		err = s.store.TransferOwnership(ctx, m.mg.Name, u.Username)
	default:
		s.back(w, r, back, "Unknown action.", true)
		return
	}
	if err != nil {
		s.back(w, r, back, "Something went wrong. Try again.", true)
		return
	}
	owners, _ := s.store.Owners(ctx, m.mg.Name)
	s.audit(r, "group.owner_"+action, m.mg.Name, u.Username)
	notifyUsers := map[string]bool{u.Username: true}
	for _, o := range append(m.mg.Owners, owners...) {
		notifyUsers[o] = true
	}
	ownerList := strings.Join(owners, ", ")
	if ownerList == "" {
		ownerList = "(none)"
	}
	s.notifier.Notify(ctx, "ownership_changed", s.emailsOf(ctx, m.dir, sortedKeys(notifyUsers)), notify.Data{"Group": m.mg.Name, "By": sessionFrom(r).Username, "Owners": ownerList})
	s.back(w, r, back, "Owners updated.", false)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != m.mg.Name {
		s.back(w, r, s.groupPath(m.mg.Name), "Type the group name to confirm deleting it.", true)
		return
	}
	if m.group != nil {
		if err := m.dir.DeleteGroup(r.Context(), m.mg.Name); err != nil {
			s.back(w, r, s.groupPath(m.mg.Name), userFacingGroup(err), true)
			return
		}
	}
	if err := s.store.RemoveManagedGroup(r.Context(), m.mg.Name); err != nil {
		s.back(w, r, "/mod/groups", "Deleted from the directory, but SAM's record could not be removed.", true)
		return
	}
	s.audit(r, "group.deleted", m.mg.Name, "")
	s.back(w, r, "/mod/groups", "Group "+m.mg.Name+" deleted.", false)
}

func (s *Server) releaseGroup(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadManaged(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveManagedGroup(r.Context(), m.mg.Name); err != nil {
		s.back(w, r, s.groupPath(m.mg.Name), "Something went wrong. Try again.", true)
		return
	}
	s.audit(r, "group.released", m.mg.Name, "no longer managed (directory group kept)")
	s.back(w, r, "/mod/groups", m.mg.Name+" is no longer managed here. The directory group was kept.", false)
}

// ---- group requests ----

func (s *Server) groupRequestForm(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "Request a group", "groups")
	p.Form = url.Values{}
	s.render(w, r, http.StatusOK, "group_request", p)
}

func (s *Server) groupRequest(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	p := s.page(w, r, "Request a group", "groups")
	p.Form = r.PostForm
	again := func(msg string) {
		p.Error = msg
		s.render(w, r, http.StatusUnprocessableEntity, "group_request", p)
	}
	req := &store.GroupRequest{
		Name:          strings.ToLower(strings.TrimSpace(r.PostFormValue("name"))),
		Description:   clean(r.PostFormValue("description"), 256),
		Justification: cleanText(r.PostFormValue("justification"), 2000),
		Requester:     se.Username,
		Status:        store.StatusPending,
	}
	re, err := regexp.Compile(s.settings.Get("group_name_pattern"))
	if err != nil || !re.MatchString(req.Name) {
		again("That group name is not allowed: use lower-case letters, digits, dots, dashes or underscores, starting with a letter.")
		return
	}
	if s.reserved(req.Name) {
		again("That name is reserved.")
		return
	}
	if req.Description == "" || req.Justification == "" {
		again("A description and a reason are required.")
		return
	}
	if !s.limiter.allow("greq:"+se.Username, 10, 24*time.Hour) {
		again("You have made too many requests today.")
		return
	}
	dir, err := s.Dir()
	if err != nil {
		again("The directory is not configured.")
		return
	}
	if _, err := dir.GetGroup(r.Context(), req.Name); err == nil {
		again("A group with that name already exists.")
		return
	}
	if dup, _ := s.store.PendingGroupRequestFor(r.Context(), req.Name); dup {
		again("A request for that group is already waiting.")
		return
	}
	if err := s.store.CreateGroupRequest(r.Context(), req); err != nil {
		again("Something went wrong. Try again.")
		return
	}
	s.audit(r, "group_request.created", req.Name, req.Description)
	s.notifier.Notify(r.Context(), "moderators_new_group", s.moderatorEmails(r.Context(), dir), notify.Data{
		"Group": req.Name, "Requester": se.Username, "Description": req.Description, "Justification": req.Justification, "Link": s.link("/mod/group-requests", nil),
	})
	s.back(w, r, "/groups", "Your request for "+req.Name+" was sent to the moderators.", false)
}

func userFacingGroup(err error) string {
	if strings.Contains(err.Error(), "at least one member") {
		return "This directory requires a group to keep at least one member."
	}
	return userFacing(err)
}
