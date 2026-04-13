package iam

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request types ─────────────────────────────────────────────────────────────

type onboardRequest struct {
	Provider        string  `json:"provider"    binding:"required"`
	ProviderID      string  `json:"provider_id" binding:"required"`
	Email           *string `json:"email"`
	Phone           *string `json:"phone"`
	InvitationToken *string `json:"invitation_token"`
	TenantName      string  `json:"org_name"`
	TenantSlug      string  `json:"org_slug"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleOnboard is a public endpoint that finds-or-creates a user and either
// accepts an invitation or creates a new organization.
func (m *Module) handleOnboard(c *gin.Context) {
	var req onboardRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	// Resolve the platform tenant for new org creation.
	var platformID uuid.UUID
	if req.InvitationToken == nil || *req.InvitationToken == "" {
		if req.TenantName == "" || req.TenantSlug == "" {
			sdk.Error(c, sdk.BadRequest("org_name and org_slug are required when onboarding without an invitation"))
			return
		}
		// Get platform ID from context (set by kernel middleware / config).
		if pid, ok := c.Get("platform_id"); ok {
			platformID = pid.(uuid.UUID)
		} else {
			sdk.Error(c, sdk.Internal("platform_id not available in context"))
			return
		}
	}

	out, err := m.onboard.Execute(c.Request.Context(), OnboardInput{
		Provider:        req.Provider,
		ProviderID:      req.ProviderID,
		Email:           req.Email,
		Phone:           req.Phone,
		InvitationToken: req.InvitationToken,
		TenantName:      req.TenantName,
		TenantSlug:      req.TenantSlug,
		PlatformID:      platformID,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	if out.IsNew {
		sdk.Created(c, out)
	} else {
		sdk.OK(c, out)
	}
}
