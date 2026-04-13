package iam

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request types ─────────────────────────────────────────────────────────────

type createRoleRequest struct {
	Slug        string  `json:"slug"        binding:"required,min=3,max=63"`
	Name        string  `json:"name"        binding:"required,min=1,max=120"`
	Description *string `json:"description"`
}

type updateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type setPermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

type assignRoleRequest struct {
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

// ── Role handlers (tenant-scoped) ─────────────────────────────────────────────

// handleListRoles returns all roles defined for the current tenant.
func (m *Module) handleListRoles(c *gin.Context) {
	tid := tenantID(c)

	roles, err := m.roles.ListByTenant(c.Request.Context(), tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, roles)
}

// handleCreateRole creates a new custom role in the current tenant.
func (m *Module) handleCreateRole(c *gin.Context) {
	tid := tenantID(c)

	var req createRoleRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	role, err := m.roles.Create(c.Request.Context(), CreateRoleInput{
		TenantID:    tid,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "role",
		ResourceID: role.ID.String(),
		Changes: map[string]sdk.AuditChange{
			"slug": {New: req.Slug},
			"name": {New: req.Name},
		},
	})

	sdk.Created(c, role)
}

// handleGetRole returns a specific role by ID.
func (m *Module) handleGetRole(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	role, err := m.roles.GetByID(c.Request.Context(), id)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, role)
}

// handleUpdateRole updates a custom role.
func (m *Module) handleUpdateRole(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	var req updateRoleRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	role, err := m.roles.Update(c.Request.Context(), id, UpdateRoleInput{
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "role",
		ResourceID: id.String(),
	})

	sdk.OK(c, role)
}

// handleDeleteRole deletes a custom role.
func (m *Module) handleDeleteRole(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := m.roles.Delete(c.Request.Context(), id); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "role",
		ResourceID: id.String(),
	})

	sdk.NoContent(c)
}

// ── Role Permission handlers ──────────────────────────────────────────────────

// handleSetRolePermissions replaces all permissions for a role.
func (m *Module) handleSetRolePermissions(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	var req setPermissionsRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	if err := m.roles.SetPermissions(c.Request.Context(), id, req.Permissions); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "role_permissions",
		ResourceID: id.String(),
	})

	sdk.NoContent(c)
}

// handleGetRolePermissions returns the permissions for a role.
func (m *Module) handleGetRolePermissions(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	perms, err := m.repo.GetRolePermissions(c.Request.Context(), id)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, perms)
}

// ── Role Assignment handlers ──────────────────────────────────────────────────

// handleAssignRole assigns a role to a member.
func (m *Module) handleAssignRole(c *gin.Context) {
	memberID, err := parseUUID(c, "member_id")
	if err != nil {
		return
	}

	var req assignRoleRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	if err := m.roles.AssignToMember(c.Request.Context(), memberID, req.RoleID); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "member_role",
		ResourceID: memberID.String(),
		Changes: map[string]sdk.AuditChange{
			"role_id": {New: req.RoleID.String()},
		},
	})

	sdk.NoContent(c)
}

// handleRevokeRole removes a role from a member.
func (m *Module) handleRevokeRole(c *gin.Context) {
	memberID, err := parseUUID(c, "member_id")
	if err != nil {
		return
	}
	roleID, err := parseUUID(c, "role_id")
	if err != nil {
		return
	}

	if err := m.roles.RevokeFromMember(c.Request.Context(), memberID, roleID); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "member_role",
		ResourceID: memberID.String(),
	})

	sdk.NoContent(c)
}

// handleGetMemberRoles returns all roles assigned to a member.
func (m *Module) handleGetMemberRoles(c *gin.Context) {
	memberID, err := parseUUID(c, "member_id")
	if err != nil {
		return
	}

	roles, err := m.roles.GetMemberRoles(c.Request.Context(), memberID)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, roles)
}

// handleListPermissions returns the catalog of all available permissions.
// TODO: Once the SDK exposes ctx.ListPermissions() for cross-module catalogs,
// use that instead of only returning the IAM module's own permissions.
func (m *Module) handleListPermissions(c *gin.Context) {
	manifest := m.Manifest()
	sdk.OK(c, manifest.Permissions)
}
