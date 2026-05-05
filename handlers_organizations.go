package iam

import (
	"encoding/json"

	"github.com/edgescaleDev/kernel/sdk"
	"github.com/gin-gonic/gin"
)

// ── Request types ─────────────────────────────────────────────────────────────

type createOrganizationRequest struct {
	Name     string          `json:"name" binding:"required,min=1,max=120"`
	Slug     string          `json:"slug" binding:"omitempty,min=3,max=63"`
	LogoURL  *string         `json:"logo_url"`
	Metadata json.RawMessage `json:"metadata"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleCreateOrganization creates a new organization under the platform tenant
// and assigns the authenticated user as the founding admin.
//
// The entire operation (org + membership + roles + assignment) runs in a
// single database transaction. If any step fails, nothing is committed.
func (m *Module) handleCreateOrganization(c *gin.Context) {
	uid := userID(c)
	if uid.String() == "00000000-0000-0000-0000-000000000000" {
		sdk.Error(c, sdk.Unauthorized("user not registered; call POST /register first"))
		return
	}

	var req createOrganizationRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	pid, err := m.platformTenantID(c.Request.Context())
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	out, err := m.registration.CreateOrganization(c.Request.Context(), CreateOrgForUserInput{
		UserID:     uid,
		PlatformID: pid,
		Name:       req.Name,
		Slug:       req.Slug,
		LogoURL:    req.LogoURL,
		Metadata:   req.Metadata,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "organization",
		ResourceID: out.Tenant.ID.String(),
		Changes: map[string]sdk.AuditChange{
			"slug": {New: req.Slug},
			"name": {New: req.Name},
		},
	})

	sdk.Created(c, out)
}
