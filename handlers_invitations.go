package iam

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request types ─────────────────────────────────────────────────────────────

type createInvitationRequest struct {
	Email  *string   `json:"email"`
	Phone  *string   `json:"phone"`
	RoleID uuid.UUID `json:"role_id" binding:"required"`
}

// ── Invitation handlers (tenant-scoped) ───────────────────────────────────────

// handleListInvitations returns a paginated list of invitations for the current tenant.
func (m *Module) handleListInvitations(c *gin.Context) {
	tid := tenantID(c)
	page := sdk.ParsePageRequest(c)

	result, err := m.invitations.List(c.Request.Context(), tid, page)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.List(c, result.Items, result.Meta)
}

// handleCreateInvitation creates or re-sends an invitation.
func (m *Module) handleCreateInvitation(c *gin.Context) {
	tid := tenantID(c)
	uid := userID(c)

	var req createInvitationRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	out, err := m.invitations.Create(c.Request.Context(), CreateInvitationInput{
		TenantID:  tid,
		InvitedBy: uid,
		Email:     req.Email,
		Phone:     req.Phone,
		RoleID:    req.RoleID,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "invitation",
		ResourceID: out.Invitation.ID.String(),
	})

	// Return the invitation with the raw token (caller must send it to invitee).
	sdk.Created(c, map[string]any{
		"invitation": out.Invitation,
		"token":      out.RawToken,
	})
}

// handleGetInvitation returns a specific invitation by ID.
func (m *Module) handleGetInvitation(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	inv, err := m.invitations.GetByID(c.Request.Context(), id)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, inv)
}

// handleRevokeInvitation revokes a pending invitation.
func (m *Module) handleRevokeInvitation(c *gin.Context) {
	id, err := parseUUID(c, "id")
	if err != nil {
		return
	}

	if err := m.invitations.Revoke(c.Request.Context(), id); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "invitation",
		ResourceID: id.String(),
		Changes: map[string]sdk.AuditChange{
			"status": {New: "revoked"},
		},
	})

	sdk.NoContent(c)
}
