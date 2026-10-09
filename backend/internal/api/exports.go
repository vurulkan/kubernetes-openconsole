package api

import (
	"encoding/csv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CSV exports of the access model for reviews / audits: who exists, how they
// sign in, and which groups / roles they get. Admin only; each export is
// audited.

func (s *Server) handleExportUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	groupNames, err := s.groupNames(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=users.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"username", "source", "admin", "active", "must_change_password", "groups", "created_at"})
	for _, u := range users {
		ids, _ := s.store.GetUserGroups(ctx, u.ID)
		_ = cw.Write([]string{
			u.Username,
			u.AuthSource,
			strconv.FormatBool(u.IsAdmin),
			strconv.FormatBool(u.IsActive),
			strconv.FormatBool(u.MustChangePassword),
			joinNames(ids, groupNames),
			u.CreatedAt.In(s.timezone).Format(time.RFC3339),
		})
	}
	cw.Flush()
	s.recordAudit(r, "admin.export", "-", "users", strconv.Itoa(len(users)))
}

func (s *Server) handleExportGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups, err := s.store.ListGroups(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	roles, err := s.store.ListRoles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}
	roleNames := map[int]string{}
	for _, role := range roles {
		roleNames[role.ID] = role.Name
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	members := map[int][]string{}
	for _, u := range users {
		ids, _ := s.store.GetUserGroups(ctx, u.ID)
		for _, id := range ids {
			members[id] = append(members[id], u.Username)
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=groups.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"group", "members", "roles"})
	for _, g := range groups {
		roleIDs, _ := s.store.GetGroupRoles(ctx, g.ID)
		m := members[g.ID]
		sort.Strings(m)
		_ = cw.Write([]string{g.Name, strings.Join(m, "; "), joinNames(roleIDs, roleNames)})
	}
	cw.Flush()
	s.recordAudit(r, "admin.export", "-", "groups", strconv.Itoa(len(groups)))
}

func (s *Server) groupNames(r *http.Request) (map[int]string, error) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		return nil, err
	}
	out := make(map[int]string, len(groups))
	for _, g := range groups {
		out[g.ID] = g.Name
	}
	return out, nil
}

// joinNames maps ids to names, sorted, "; "-separated (commas stay free for
// CSV readers that split naively).
func joinNames(ids []int, names map[int]string) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}
