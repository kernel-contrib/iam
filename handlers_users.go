package iam

import (
	"github.com/gin-gonic/gin"
	"go.edgescale.dev/kernel/sdk"
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
