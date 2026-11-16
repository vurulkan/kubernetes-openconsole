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
		w.WriteHeader(http.StatusInternalServerError)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if msg := checkUsername(request.Username); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
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
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		password = request.Password
	case models.AuthSourceAzure:
		// Never usable: Azure AD accounts don't sign in with a password.
		password = randomPassword()
	default:
		writeError(w, http.StatusBadRequest, "source must be local or azure (LDAP users are imported)")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id, err := s.store.CreateUser(r.Context(), request.Username, hash)
	if err != nil {
		writeError(w, http.StatusConflict, "a user with this name already exists")
		return
	}
	if source != models.AuthSourceLocal {
		_ = s.store.SetUserAuthSource(r.Context(), id, source)
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(request.GroupIDs) > 0 {
		if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
			writeError(w, http.StatusBadRequest, "user created, but the groups could not be set: "+err.Error())
			return
		}
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindUser, ResourceName: user.Username,
		Details: audit.D{"account_source": source, "is_admin": user.IsAdmin, "groups": len(request.GroupIDs)}})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The UI always sends the name; a script that leaves it out must not
	// blank it (the account could no longer sign in).
	request.Username = strings.TrimSpace(request.Username)
	if msg := checkUsername(request.Username); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Guard: do not let the last active admin be demoted or deactivated — the
	// system would be unmanageable afterwards. "Last" is counted BEFORE this
	// update is applied; if the user is currently admin+active and is about
	// to lose either flag, require at least one other admin to survive.
	if user.IsAdmin && user.IsActive && (!request.IsAdmin || !request.IsActive) {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if count <= 1 {
			writeError(w, http.StatusConflict,
				"cannot demote or deactivate the last active administrator")
			return
		}
	}
	if o := request.APIAccessOverride; o != nil && *o != "" && !rbac.ValidMode(*o) {
		writeError(w, http.StatusBadRequest, errAPIAccess)
		return
	}
	before := *user
	user.Username = request.Username
	user.IsActive = request.IsActive
	user.IsAdmin = request.IsAdmin
	if err := s.store.UpdateUser(r.Context(), *user); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
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
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user.APIAccessOverride = *o
		d["changed"] = append(changed, "api_access")
		d["api_access"] = *o
		if *o == "" {
			d["api_access"] = "roles"
		}
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindUser, ResourceName: user.Username, Details: d})
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	caller, _ := s.userForRequest(r)
	if caller != nil && caller.ID == id {
		writeError(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	target, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Guard: deleting the last active admin would strand the system.
	if target.IsAdmin && target.IsActive {
		count, err := s.store.CountActiveAdmins(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if count <= 1 {
			writeError(w, http.StatusConflict,
				"cannot delete the last active administrator")
			return
		}
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindUser, ResourceName: target.Username,
		Details: audit.D{"account_source": target.AuthSource, "is_admin": target.IsAdmin}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		GroupIDs []int `json:"groupIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.SetUserGroups(r.Context(), id, request.GroupIDs); err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, Outcome: audit.Failed, Reason: failReason(err),
			ResourceType: audit.KindUser, ResourceName: s.userNameByID(r, id), Details: failDetails(err, audit.D{"changed": []string{"groups"}})})
		if errors.Is(err, store.ErrUnknownReference) {
			writeError(w, http.StatusBadRequest, "unknown user or group id")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindUser, ResourceName: s.userNameByID(r, id),
		Details: audit.D{"changed": []string{"groups"}, "groups": len(request.GroupIDs)}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetUserGroups(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ids, err := s.store.GetUserGroups(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"groupIds": ids})
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": groups})
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, err := s.store.CreateGroup(r.Context(), request.Name)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindGroup, ResourceName: request.Name})
	writeJSON(w, http.StatusCreated, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateGroup(r.Context(), id, request.Name); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindGroup, ResourceName: request.Name, Details: audit.D{"changed": []string{"name"}}})
	writeJSON(w, http.StatusOK, models.Group{ID: id, Name: request.Name})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	name := s.groupNameByID(r, id)
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindGroup, ResourceName: name, Details: audit.D{"id": id}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		RoleIDs []int `json:"roleIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.SetGroupRoles(r.Context(), id, request.RoleIDs); err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, Outcome: audit.Failed, Reason: failReason(err),
			ResourceType: audit.KindGroup, ResourceName: s.groupNameByID(r, id), Details: failDetails(err, audit.D{"changed": []string{"roles"}})})
		if errors.Is(err, store.ErrUnknownReference) {
			writeError(w, http.StatusBadRequest, "unknown group or role id")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindGroup, ResourceName: s.groupNameByID(r, id),
		Details: audit.D{"changed": []string{"roles"}, "count": len(request.RoleIDs)}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleGetGroupRoles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ids, err := s.store.GetGroupRoles(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roleIds": ids})
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.APIAccess == "" {
		request.APIAccess = rbac.AccessSafeRead
	}
	if !rbac.ValidMode(request.APIAccess) {
		writeError(w, http.StatusBadRequest, errAPIAccess)
		return
	}
	id, err := s.store.CreateRole(r.Context(), request.Name, request.Description)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	if request.APIAccess != rbac.AccessSafeRead {
		if err := s.store.SetRoleAPIAccess(r.Context(), id, request.APIAccess); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, ResourceType: audit.KindRole, ResourceName: request.Name,
		Details: audit.D{"api_access": request.APIAccess}})
	writeJSON(w, http.StatusCreated, models.Role{ID: id, Name: request.Name, Description: request.Description, APIAccess: request.APIAccess})
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		APIAccess   *string `json:"apiAccess"` // absent = unchanged
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.APIAccess != nil && !rbac.ValidMode(*request.APIAccess) {
		writeError(w, http.StatusBadRequest, errAPIAccess)
		return
	}
	roles, err := s.store.ListRoles(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	i := slices.IndexFunc(roles, func(x models.Role) bool { return x.ID == id })
	if i < 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	role := models.Role{ID: id, Name: request.Name, Description: request.Description, APIAccess: roles[i].APIAccess}
	if err := s.store.UpdateRole(r.Context(), role); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var d audit.D
	if request.APIAccess != nil && *request.APIAccess != role.APIAccess {
		if err := s.store.SetRoleAPIAccess(r.Context(), id, *request.APIAccess); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		role.APIAccess = *request.APIAccess
		d = audit.D{"changed": []string{"api_access"}, "api_access": role.APIAccess}
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbUpdate, ResourceType: audit.KindRole, ResourceName: request.Name, Details: d})
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	name := s.roleNameByID(r, id)
	if err := s.store.DeleteRole(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.auditEvent(r, models.AuditLog{Verb: audit.VerbDelete, ResourceType: audit.KindRole, ResourceName: name, Details: audit.D{"id": id}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	permissions, err := s.store.ListNamespacePermissions(r.Context(), roleID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": permissions})
}

func (s *Server) handleAddRolePermission(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request struct {
		ClusterID int    `json:"clusterId"` // 0 or omitted → "all clusters" wildcard
		Namespace string `json:"namespace"`
		Resource  string `json:"resource"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := s.store.AddNamespacePermission(r.Context(), roleID, request.ClusterID, request.Namespace, request.Resource, request.Action); err != nil {
		s.auditEvent(r, models.AuditLog{Verb: audit.VerbCreate, Outcome: audit.Failed, Reason: failReason(err),
			ResourceType: audit.KindPermission, ResourceName: strconv.Itoa(roleID), Namespace: request.Namespace,
			Details: failDetails(err, audit.D{"grant": request.Resource + ":" + request.Action})})
		if errors.Is(err, store.ErrUnknownReference) {
			writeError(w, http.StatusNotFound, "role not found")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	clusterName := ""
	if request.ClusterID > 0 {
		clusterName, _ = s.store.GetClusterName(r.Context(), request.ClusterID)
	}
	s.recordPermissionAudit(r, audit.VerbCreate, models.NamespacePermission{
		RoleID: roleID, ClusterID: request.ClusterID, ClusterName: clusterName,
		Namespace: request.Namespace, Resource: request.Resource, Action: request.Action,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleDeletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	perm, err := s.store.GetNamespacePermission(r.Context(), id)
	if err != nil {
		perm = &models.NamespacePermission{ID: id}
	}
	if err := s.store.DeleteNamespacePermission(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.recordPermissionAudit(r, audit.VerbDelete, *perm)
	w.WriteHeader(http.StatusNoContent)
}
