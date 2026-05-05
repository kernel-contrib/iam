package iam

import (
	"github.com/edgescaleDev/kernel/sdk"
	"github.com/gin-gonic/gin"
)

// ── Request types ─────────────────────────────────────────────────────────────

type updateMeRequest struct {
	Email     *string `json:"email"`
	Phone     *string `json:"phone"`
	Name      *string `json:"name"`
	AvatarURL *string `json:"avatar_url"`
	Locale    *string `json:"locale"`
}

// ── Self-service handlers ─────────────────────────────────────────────────────

// handleGetMe returns the authenticated user's profile.
func (m *Module) handleGetMe(c *gin.Context) {
	uid := userID(c)

	user, err := m.users.GetByID(c.Request.Context(), uid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, user)
}

// handleUpdateMe updates the authenticated user's own profile.
func (m *Module) handleUpdateMe(c *gin.Context) {
	uid := userID(c)

	var req updateMeRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	user, err := m.users.Update(c.Request.Context(), uid, UpdateUserInput{
		Email:     req.Email,
		Phone:     req.Phone,
		Name:      req.Name,
		AvatarURL: req.AvatarURL,
		Locale:    req.Locale,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "user",
		ResourceID: uid.String(),
	})

	sdk.OK(c, user)
}

// handleEraseMe triggers GDPR erasure for the authenticated user.
func (m *Module) handleEraseMe(c *gin.Context) {
	uid := userID(c)

	if err := m.users.Erase(c.Request.Context(), uid); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "user",
		ResourceID: uid.String(),
	})

	sdk.NoContent(c)
}

// handleListMyTenants returns all tenants the authenticated user is a member of.
func (m *Module) handleListMyTenants(c *gin.Context) {
	uid := userID(c)

	members, err := m.repo.ListMembershipsByUser(c.Request.Context(), uid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, members)
}

// myRolesResponse combines the member's assigned roles with the effective
// (resolved) permission set for the current tenant context.
type myRolesResponse struct {
	Roles       []MemberRole `json:"roles"`
	Permissions []string     `json:"permissions"`
}

// handleGetMyRoles returns the authenticated user's roles and resolved
// permissions for the current tenant. No special permission is needed since
// users can only view their own access.
func (m *Module) handleGetMyRoles(c *gin.Context) {
	uid := userID(c)
	tid := tenantID(c)

	// Find the user's membership in this tenant.
	member, err := m.repo.FindMemberByUserAndTenant(c.Request.Context(), uid, tid)
	if err != nil {
		if isNotFoundErr(err) {
			sdk.Error(c, sdk.NotFound("membership", uid))
			return
		}
		sdk.FromError(c, err)
		return
	}

	// Get the assigned roles (with permission keys preloaded).
	roles, err := m.roles.GetMemberRoles(c.Request.Context(), member.ID)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	// Resolve effective permissions (accounts for tenant hierarchy and RBAC mode).
	perms, err := m.roles.ResolvePermissions(c.Request.Context(), uid, tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, myRolesResponse{
		Roles:       roles,
		Permissions: perms,
	})
}
