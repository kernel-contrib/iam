package iam

import "github.com/edgescaleDev/kernel/sdk"

// RouteHandlers mounts all HTTP endpoints on the kernel router.
// Routes are split into two groups:
//   - Global: authenticated self-service (/v1/iam/...)
//   - Tenant-scoped: require tenant context (/v1/:tenant_id/iam/...)
func (m *Module) RouteHandlers() []sdk.RouteHandler {
	return []sdk.RouteHandler{
		{
			Type: sdk.RouteClient, Register: m.registerClientRoutes,
		},
	}
}

func (m *Module) registerClientRoutes(router *sdk.Router) {
	// ── Global routes (self-service, no tenant context) ───────────────────
	// Permissions catalog (all module permissions).
	router.GET("/permissions", PermRead, m.handleListPermissions)

	// Self-service registration. Uses sdk.Self because the IAM user record
	// may not exist yet -- the kernel only needs a valid IdP token.
	router.POST("/register", sdk.Self, m.handleRegister)

	// Self-service organization creation. Uses sdk.Self because the user
	// must already be registered (internal_user_id is required).
	router.POST("/organizations", sdk.Self, m.handleCreateOrganization)

	// Self-service invitation preview and acceptance. Uses sdk.Self because
	// the user must already be registered.
	router.POST("/invitations/preview", sdk.Self, m.handlePreviewInvitation)
	router.POST("/invitations/accept", sdk.Self, m.handleAcceptInvitation)

	// Self-service profile.
	router.GET("/me", sdk.Self, m.handleGetMe)
	router.PATCH("/me", sdk.Self, m.handleUpdateMe)
	router.DELETE("/me", sdk.Self, m.handleEraseMe)

	// List tenants the authenticated user belongs to.
	router.GET("/tenants", sdk.Self, m.handleListMyTenants)

	// ── Tenant-scoped self-service routes ─────────────────────────────────
	// These require tenant context but only access the caller's own data.
	t := router.Tenant()
	t.GET("/me/roles", sdk.Self, m.handleGetMyRoles)

	// Current tenant.
	t.GET("/tenant", PermReader, m.handleGetTenant)
	t.PATCH("/tenant", PermWriter, m.handleUpdateTenant)
	t.DELETE("/tenant", PermWriter, m.handleDeleteTenant)

	// Branches (child tenants).
	t.GET("/branches", PermReader, m.handleListChildren)
	t.POST("/branches", PermWriter, m.handleCreateBranch)
	t.GET("/branches/:id", PermReader, m.handleGetBranch)
	t.PATCH("/branches/:id", PermWriter, m.handleUpdateBranch)
	t.DELETE("/branches/:id", PermWriter, m.handleDeleteBranch)

	// Members.
	t.GET("/members", PermReader, m.handleListMembers)
	t.POST("/members", PermWriter, m.handleAddMember)
	t.GET("/members/:id", PermReader, m.handleGetMember)
	t.PATCH("/members/:id", PermWriter, m.handleUpdateMember)
	t.DELETE("/members/:id", PermWriter, m.handleRemoveMember)

	// Member role assignments.
	t.GET("/members/:id/roles", PermReader, m.handleGetMemberRoles)
	t.POST("/members/:id/roles", PermWriter, m.handleAssignRole)
	t.DELETE("/members/:id/roles/:role_id", PermWriter, m.handleRevokeRole)

	// Roles.
	t.GET("/roles", PermReader, m.handleListRoles)
	t.POST("/roles", PermWriter, m.handleCreateRole)
	t.GET("/roles/:id", PermReader, m.handleGetRole)
	t.PATCH("/roles/:id", PermWriter, m.handleUpdateRole)
	t.DELETE("/roles/:id", PermWriter, m.handleDeleteRole)

	// Role permissions.
	t.GET("/roles/:id/permissions", PermReader, m.handleGetRolePermissions)
	t.PUT("/roles/:id/permissions", PermWriter, m.handleSetRolePermissions)

	// Invitations.
	t.GET("/invitations", PermReader, m.handleListInvitations)
	t.POST("/invitations", PermWriter, m.handleCreateInvitation)
	t.GET("/invitations/:id", PermReader, m.handleGetInvitation)
	t.DELETE("/invitations/:id", PermWriter, m.handleRevokeInvitation)

	// Auth providers (per-tenant IdP configuration).
	t.GET("/auth-providers", PermReader, m.handleListAuthProviders)
	t.PUT("/auth-providers", PermWriter, m.handleSetAuthProviders)

}
