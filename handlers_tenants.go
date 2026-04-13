package iam

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request types ─────────────────────────────────────────────────────────────

type createBranchRequest struct {
	Slug string `json:"slug" binding:"required,min=3,max=63"`
	Name string `json:"name" binding:"required,min=1,max=120"`
}

type updateTenantRequest struct {
	Name    *string `json:"name"`
	LogoURL *string `json:"logo_url"`
}

// ── Tenant handlers (tenant-scoped) ───────────────────────────────────────────

// handleGetTenant returns the current tenant's details.
func (m *Module) handleGetTenant(c *gin.Context) {
	tid := tenantID(c)

	tenant, err := m.tenants.GetByID(c.Request.Context(), tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, tenant)
}

// handleUpdateTenant updates the current tenant.
func (m *Module) handleUpdateTenant(c *gin.Context) {
	tid := tenantID(c)

	var req updateTenantRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	tenant, err := m.tenants.Update(c.Request.Context(), tid, UpdateTenantInput{
		Name:    req.Name,
		LogoURL: req.LogoURL,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "tenant",
		ResourceID: tid.String(),
	})

	sdk.OK(c, tenant)
}

// handleDeleteTenant deactivates the current tenant.
func (m *Module) handleDeleteTenant(c *gin.Context) {
	tid := tenantID(c)

	if err := m.tenants.Deactivate(c.Request.Context(), tid); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "tenant",
		ResourceID: tid.String(),
	})

	sdk.NoContent(c)
}

// ── Branch (child tenant) handlers ────────────────────────────────────────────

// handleListChildren returns branches under the current tenant.
func (m *Module) handleListChildren(c *gin.Context) {
	tid := tenantID(c)

	children, err := m.tenants.ListChildren(c.Request.Context(), tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, children)
}

// handleCreateBranch creates a new branch under the current tenant (org).
func (m *Module) handleCreateBranch(c *gin.Context) {
	tid := tenantID(c)

	var req createBranchRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	branch, err := m.tenants.CreateBranch(c.Request.Context(), CreateBranchInput{
		Slug:     req.Slug,
		Name:     req.Name,
		TenantID: tid,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "tenant",
		ResourceID: branch.ID.String(),
		Changes: map[string]sdk.AuditChange{
			"slug": {New: req.Slug},
			"name": {New: req.Name},
			"type": {New: string(TenantTypeBranch)},
		},
	})

	sdk.Created(c, branch)
}

// handleGetBranch returns a specific child tenant by ID.
func (m *Module) handleGetBranch(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	branch, err := m.tenants.GetByID(c.Request.Context(), id)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, branch)
}

// handleUpdateBranch updates a specific child tenant.
func (m *Module) handleUpdateBranch(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	var req updateTenantRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	branch, err := m.tenants.Update(c.Request.Context(), id, UpdateTenantInput{
		Name:    req.Name,
		LogoURL: req.LogoURL,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "tenant",
		ResourceID: id.String(),
	})

	sdk.OK(c, branch)
}

// handleDeleteBranch deactivates a specific child tenant.
func (m *Module) handleDeleteBranch(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := m.tenants.Deactivate(c.Request.Context(), id); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "tenant",
		ResourceID: id.String(),
	})

	sdk.NoContent(c)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseUUID(c *gin.Context, param string) (uuid.UUID, error) {
	raw := c.Param(param)
	id, err := uuid.Parse(raw)
	if err != nil {
		sdk.Error(c, sdk.BadRequest(fmt.Sprintf("invalid %s: must be a UUID", param)))
		return uuid.Nil, err
	}
	return id, nil
}
