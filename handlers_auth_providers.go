package iam

import (
	"github.com/gin-gonic/gin"
	"go.edgescale.dev/kernel/sdk"
)

// ── Request/Response types ────────────────────────────────────────────────────

type authProviderEntry struct {
	ProviderName string    `json:"provider_name" binding:"required,min=1,max=100"`
	IsEnabled    bool      `json:"is_enabled"`
	Config       sdk.JSONB `json:"config,omitempty"`
}

type setAuthProvidersRequest struct {
	Providers []authProviderEntry `json:"providers" binding:"required"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleListAuthProviders returns all configured auth providers for the tenant.
// If no configs exist, the response is an empty list (meaning all providers are allowed).
func (m *Module) handleListAuthProviders(c *gin.Context) {
	tid := tenantID(c)

	configs, err := m.repo.ListAuthConfig(c.Request.Context(), tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, configs)
}

// handleSetAuthProviders replaces the entire auth provider allowlist for the tenant.
// Sending an empty providers array removes all restrictions (open access).
func (m *Module) handleSetAuthProviders(c *gin.Context) {
	tid := tenantID(c)

	var req setAuthProvidersRequest
	if !sdk.BindAndValidate(c, &req) {
		return
	}

	// Build config entries.
	configs := make([]TenantAuthConfig, 0, len(req.Providers))
	for _, p := range req.Providers {
		configs = append(configs, TenantAuthConfig{
			TenantID:     tid,
			ProviderName: p.ProviderName,
			IsEnabled:    p.IsEnabled,
			Config:       p.Config,
		})
	}

	if err := m.repo.SetAuthConfig(c.Request.Context(), tid, configs); err != nil {
		sdk.FromError(c, err)
		return
	}

	m.ctx.Audit.Log(c.Request.Context(), sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "tenant_auth_config",
		ResourceID: tid.String(),
	})

	m.ctx.Bus.Publish(c.Request.Context(), "iam.tenant.auth_config.updated", map[string]any{
		"tenant_id": tid,
		"providers": req.Providers,
	})

	// Return the new state.
	updated, err := m.repo.ListAuthConfig(c.Request.Context(), tid)
	if err != nil {
		sdk.FromError(c, err)
		return
	}

	sdk.OK(c, updated)
}
