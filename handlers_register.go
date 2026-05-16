package iam

import (
	"encoding/json"

	"github.com/kernel-contrib/sdk"
	"github.com/gin-gonic/gin"
)

// ── Request/Response types ────────────────────────────────────────────────────

type registerRequest struct {
	Email     *string         `json:"email"`
	Phone     *string         `json:"phone"`
	Name      *string         `json:"name"`
	AvatarURL *string         `json:"avatar_url"`
	Locale    *string         `json:"locale"`
	Timezone  *string         `json:"timezone"`
	Metadata  json.RawMessage `json:"metadata"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// handleRegister is a self-service endpoint that creates or retrieves
// the IAM user record for the authenticated identity.
//
// The provider and provider ID are read from the kernel's auth context,
// NOT from the request body. This prevents identity spoofing.
//
// Idempotent: returns 201 for new users, 200 for existing users.
func (m *Module) handleRegister(c *gin.Context) {
	provider := authProvider(c)
	providerID := authProviderID(c)

	if provider == "" || providerID == "" {
		sdk.Error(c, sdk.BadRequest("unable to resolve identity from auth context"))
		return
	}

	var req registerRequest
	// Body is optional (email, phone, name are supplemental).
	_ = c.ShouldBindJSON(&req)

	out, err := m.registration.Register(c.Request.Context(), RegisterInput{
		Provider:   provider,
		ProviderID: providerID,
		Email:      req.Email,
		Phone:      req.Phone,
		Name:       req.Name,
		AvatarURL:  req.AvatarURL,
		Locale:     req.Locale,
		Timezone:   req.Timezone,
		Metadata:   req.Metadata,
	})
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "user",
		ResourceID: out.User.ID.String(),
	})

	if out.IsNew {
		sdk.Created(c, out)
	} else {
		sdk.OK(c, out)
	}
}
