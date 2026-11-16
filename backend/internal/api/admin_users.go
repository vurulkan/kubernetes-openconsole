package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"k8s-dashboard/backend/internal/audit"
	"k8s-dashboard/backend/internal/auth"
	"k8s-dashboard/backend/internal/models"
	"k8s-dashboard/backend/internal/problem"
	"k8s-dashboard/backend/internal/rbac"
	"k8s-dashboard/backend/internal/store"
)

// maxUsernameLen bounds a user name, also the one a failed sign-in writes
// into the audit.
const maxUsernameLen = 256

// checkUsername returns why name can't be a user name, or "".
func checkUsername(name string) string {
	switch {
	case name == "":
		return "username is required"
	case len(name) > maxUsernameLen:
		return "username is too long"
	}
	return ""
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"isAdmin"`
		// Source "azure" pre-creates an Azure AD account (no password; the
		// first Microsoft sign-in uses it). Empty or "local" is a local user.
		Source   string `json:"source"`
		GroupIDs []int  `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	note := noteFor(r)
	note.Name = request.Username
	if msg := checkUsername(request.Username); msg != "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, msg)
		return
	}
	source := strings.ToLower(strings.TrimSpace(request.Source))
	if source == "" {
		source = models.AuthSourceLocal
	}
	var password string
	switch source {
	case models.AuthSourceLocal:
		if err := auth.CheckPasswordPolicy(request.Password); err != nil {
			writeErrorDetail(w, http.StatusBadRequest, problem.WeakPassword, err.Error())
			return
		}
		password = request.Password
	case models.AuthSourceAzure:
		// Never usable: Azure AD accounts don't sign in with a password.
		password = randomPassword()
	default:
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "source must be local or azure (LDAP users are imported)")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	id, err := s.store.CreateUser(r.Context(), request.Username, hash)
	if err != nil {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, "a user with this name already exists")
		return
	}
	if source != models.AuthSourceLocal {
		_ = s.store.SetUserAuthSource(r.Context(), id, source)
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	if len(request.GroupIDs) > 0 {
		if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
			writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "user created, but the groups could not be set: "+err.Error())
			return
		}
	}
	note.Details = audit.D{"account_source": source, "is_admin": user.IsAdmin, "groups": len(request.GroupIDs)}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		Username string `json:"username"`
		IsActive bool   `json:"isActive"`
		IsAdmin  bool   `json:"isAdmin"`
		// APIAccessOverride: "" = by roles, else a mode; absent = unchanged.
		APIAccessOverride *string `json:"apiAccessOverride"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	// The UI always sends the name; a script that leaves it out must not
	// blank it (the account could no longer sign in).
	request.Username = strings.TrimSpace(request.Username)
	if msg := checkUsername(request.Username); msg != "" {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, msg)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, problem.NotFound)
		return
	}
	note := noteFor(r)
	note.Name = user.Username
	// Guard: do not let the last active admin be demoted or deactivated — the
	// system would be unmanageable afterwards. "Last" is counted BEFORE this
	// update is applied; if the user is currently admin+active and is about
	// to lose either flag, require at least one other admin to survive.
	if user.IsAdmin && user.IsActive && (!request.IsAdmin || !request.IsActive) {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
		if count <= 1 {
			writeErrorDetail(w, http.StatusConflict, problem.Conflict,
				"cannot demote or deactivate the last active administrator")
			return
		}
	}
	if o := request.APIAccessOverride; o != nil && *o != "" && !rbac.ValidMode(*o) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, errAPIAccess)
		return
	}
	before := *user
	user.Username = request.Username
	user.IsActive = request.IsActive
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	// A disabled account loses its sessions now, not when the token expires.
	if before.IsActive && !user.IsActive {
		_ = s.store.RevokeAllForUser(r.Context(), user.ID)
	}
	changed := []string{}
	if before.Username != user.Username {
		changed = append(changed, "username")
	}
	if before.IsActive != user.IsActive {
		changed = append(changed, "is_active")
	}
	if before.IsAdmin != user.IsAdmin {
		changed = append(changed, "is_admin")
	}
	d := audit.D{"changed": changed, "is_admin": user.IsAdmin, "is_active": user.IsActive}
	if o := request.APIAccessOverride; o != nil && *o != before.APIAccessOverride {
		if err := s.store.SetUserAPIAccess(r.Context(), user.ID, *o); err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
		user.APIAccessOverride = *o
		d["changed"] = append(changed, "api_access")
		d["api_access"] = *o
		if *o == "" {
			d["api_access"] = "roles"
		}
	}
	note.Name, note.Details = user.Username, d
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}

	caller, _ := s.userForRequest(r)
	if caller != nil && caller.ID == id {
		writeError(w, http.StatusConflict, problem.CannotDeleteSelf)
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, problem.NotFound)
		return
	}
	note := noteFor(r)
	note.Name = target.Username
	// Guard: deleting the last active admin would strand the system.
	if target.IsAdmin && target.IsActive {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
		if count <= 1 {
			writeErrorDetail(w, http.StatusConflict, problem.Conflict,
				"cannot delete the last active administrator")
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	note.Details = audit.D{"account_source": target.AuthSource, "is_admin": target.IsAdmin}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		GroupIDs []int `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	note := noteFor(r)
	note.Name = s.userNameByID(r, id)
	if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
		note.Reason, note.Details = failReason(err), failDetails(err, audit.D{"changed": []string{"groups"}})
		if errors.Is(err, store.ErrUnknownReference) {
			writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "unknown user or group id")
			return
		}
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	note.Details = audit.D{"changed": []string{"groups"}, "groups": len(request.GroupIDs)}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	ids, err := s.store.GetUserGroups(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"groupIds": ids})
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": groups})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	noteFor(r).Name = request.Name
	id, err := s.store.CreateGroup(r.Context(), request.Name)
	if err != nil {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, "the name already exists")
		return
	}
	writeJSON(w, http.StatusCreated, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	note := noteFor(r)
	note.Name, note.Details = request.Name, audit.D{"changed": []string{"name"}}
	if err := s.store.UpdateGroup(r.Context(), id, request.Name); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	note := noteFor(r)
	note.Name, note.Details = s.groupNameByID(r, id), audit.D{"id": id}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		RoleIDs []int `json:"roleIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	note := noteFor(r)
	note.Name = s.groupNameByID(r, id)
	if err := s.store.SetGroupRoles(r.Context(), id, request.RoleIDs); err != nil {
		note.Reason, note.Details = failReason(err), failDetails(err, audit.D{"changed": []string{"roles"}})
		if errors.Is(err, store.ErrUnknownReference) {
			writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, "unknown group or role id")
			return
		}
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	note.Details = audit.D{"changed": []string{"roles"}, "count": len(request.RoleIDs)}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	ids, err := s.store.GetGroupRoles(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roleIds": ids})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": roles})
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		APIAccess   string `json:"apiAccess"` // "" = safe_read
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	note := noteFor(r)
	note.Name = request.Name
	if request.APIAccess == "" {
		request.APIAccess = rbac.AccessSafeRead
	}
	if !rbac.ValidMode(request.APIAccess) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, errAPIAccess)
		return
	}
	id, err := s.store.CreateRole(r.Context(), request.Name, request.Description)
	if err != nil {
		writeErrorDetail(w, http.StatusConflict, problem.Conflict, "the name already exists")
		return
	}
	if request.APIAccess != rbac.AccessSafeRead {
		if err := s.store.SetRoleAPIAccess(r.Context(), id, request.APIAccess); err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
	}
	note.Details = audit.D{"api_access": request.APIAccess}
	writeJSON(w, http.StatusCreated, models.Role{ID: id, Name: request.Name, Description: request.Description, APIAccess: request.APIAccess})
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		APIAccess   *string `json:"apiAccess"` // absent = unchanged
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	note := noteFor(r)
	note.Name = request.Name
	if request.APIAccess != nil && !rbac.ValidMode(*request.APIAccess) {
		writeErrorDetail(w, http.StatusBadRequest, problem.InvalidInput, errAPIAccess)
		return
	}
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	i := slices.IndexFunc(roles, func(x models.Role) bool { return x.ID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, problem.NotFound)
		return
	}
	role := models.Role{ID: id, Name: request.Name, Description: request.Description, APIAccess: roles[i].APIAccess}
	if err := s.store.UpdateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	var d audit.D
	if request.APIAccess != nil && *request.APIAccess != role.APIAccess {
		if err := s.store.SetRoleAPIAccess(r.Context(), id, *request.APIAccess); err != nil {
			writeError(w, http.StatusInternalServerError, problem.InternalError)
			return
		}
		role.APIAccess = *request.APIAccess
		d = audit.D{"changed": []string{"api_access"}, "api_access": role.APIAccess}
	}
	note.Details = d
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	note := noteFor(r)
	note.Name, note.Details = s.roleNameByID(r, id), audit.D{"id": id}
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	permissions, err := s.store.ListNamespacePermissions(r.Context(), roleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": permissions})
}

func (s *Server) handleAddRolePermission(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	var request struct {
		ClusterID int    `json:"clusterId"` // 0 or omitted → "all clusters" wildcard
		Namespace string `json:"namespace"`
		Resource  string `json:"resource"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidBody)
		return
	}
	if err := s.store.AddNamespacePermission(r.Context(), roleID, request.ClusterID, request.Namespace, request.Resource, request.Action); err != nil {
		note := noteFor(r)
		note.Name, note.Namespace = strconv.Itoa(roleID), request.Namespace
		note.Reason, note.Details = failReason(err), failDetails(err, audit.D{"grant": request.Resource + ":" + request.Action})
		if errors.Is(err, store.ErrUnknownReference) {
			writeErrorDetail(w, http.StatusNotFound, problem.NotFound, "role not found")
			return
		}
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	clusterName := ""
	if request.ClusterID > 0 {
		clusterName, _ = s.store.GetClusterName(r.Context(), request.ClusterID)
	}
	s.notePermission(r, models.NamespacePermission{
		RoleID: roleID, ClusterID: request.ClusterID, ClusterName: clusterName,
		Namespace: request.Namespace, Resource: request.Resource, Action: request.Action,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, problem.InvalidID)
		return
	}
	perm, err := s.store.GetNamespacePermission(r.Context(), id)
	if err != nil {
		perm = &models.NamespacePermission{ID: id}
	}
	s.notePermission(r, *perm)
	if err := s.store.DeleteNamespacePermission(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, problem.InternalError)
		return
	}
	s.notePermission(r, *perm)
	w.WriteHeader(http.StatusNoContent)
}
