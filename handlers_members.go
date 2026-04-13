package iam

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request types ─────────────────────────────────────────────────────────────

type addMemberRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
}

type updateMemberRequest struct {
	Status MemberStatus `json:"status" binding:"required,oneof=active suspended"`
}

// ── Member handlers (tenant-scoped) ───────────────────────────────────────────

// handleListMembers returns a paginated list of members for the current tenant.
func (m *Module) handleListMembers(c *gin.Context) {
	tid := tenantID(c)
	page := sdk.ParsePageRequest(c)

	result, err := m.members.List(c.Request.Context(), tid, page)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.List(c, result.Items, result.Meta)
}

// handleAddMember adds a user as a member of the current tenant.
func (m *Module) handleAddMember(c *gin.Context) {
	tid := tenantID(c)

	var req addMemberRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	member, err := m.members.Add(c.Request.Context(), AddMemberInput{
		UserID:   req.UserID,
		TenantID: tid,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "member",
		ResourceID: member.ID.String(),
		Changes: map[string]sdk.AuditChange{
			"user_id": {New: req.UserID.String()},
		},
	})

	sdk.Created(c, member)
}

// handleGetMember returns a specific member by ID.
func (m *Module) handleGetMember(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	member, err := m.members.GetByID(c.Request.Context(), id)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, member)
}

// handleUpdateMember updates a member's status (active/suspended).
func (m *Module) handleUpdateMember(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	var req updateMemberRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	member, err := m.members.UpdateStatus(c.Request.Context(), id, req.Status)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "member",
		ResourceID: id.String(),
		Changes: map[string]sdk.AuditChange{
			"status": {New: string(req.Status)},
		},
	})

	sdk.OK(c, member)
}

// handleRemoveMember removes a member from the current tenant.
func (m *Module) handleRemoveMember(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := m.members.Remove(c.Request.Context(), id); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "member",
		ResourceID: id.String(),
	})

	sdk.NoContent(c)
}
