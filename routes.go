package iam

import "go.edgescale.dev/kernel/sdk"

// RouteHandlers mounts all HTTP endpoints on the kernel router.
// Routes are split into two groups:
//   - Global: authenticated self-service (/v1/iam/...)
//   - Tenant-scoped: require tenant context (/v1/:tenant_id/iam/...)
//
// NOTE: Once the kernel is updated with URL-based tenant routing (Phase 0),
// tenant-scoped routes will use `router.Tenant()` instead of the full path.
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
	router.GET("/permissions", "iam.permissions.read", m.handleListPermissions)

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

	// ── Tenant-scoped routes ──────────────────────────────────────────────
	// These use tenant_id from the middleware context.
	t := router.Tenant()
	// Current tenant.
	t.GET("/tenant", "iam.tenants.read", m.handleGetTenant)
	t.PATCH("/tenant", "iam.tenants.manage", m.handleUpdateTenant)
	t.DELETE("/tenant", "iam.tenants.manage", m.handleDeleteTenant)

	// Branches (child tenants).
	t.GET("/branches", "iam.tenants.read", m.handleListChildren)
	t.POST("/branches", "iam.tenants.manage", m.handleCreateBranch)
	t.GET("/branches/:id", "iam.tenants.read", m.handleGetBranch)
	t.PATCH("/branches/:id", "iam.tenants.manage", m.handleUpdateBranch)
	t.DELETE("/branches/:id", "iam.tenants.manage", m.handleDeleteBranch)

	// Members.
	t.GET("/members", "iam.members.read", m.handleListMembers)
	t.POST("/members", "iam.members.manage", m.handleAddMember)
	t.GET("/members/:id", "iam.members.read", m.handleGetMember)
	t.PATCH("/members/:id", "iam.members.manage", m.handleUpdateMember)
	t.DELETE("/members/:id", "iam.members.manage", m.handleRemoveMember)

	// Member role assignments.
	t.GET("/members/:id/roles", "iam.roles.read", m.handleGetMemberRoles)
	t.POST("/members/:id/roles", "iam.roles.manage", m.handleAssignRole)
	t.DELETE("/members/:id/roles/:role_id", "iam.roles.manage", m.handleRevokeRole)

	// Roles.
	t.GET("/roles", "iam.roles.read", m.handleListRoles)
	t.POST("/roles", "iam.roles.manage", m.handleCreateRole)
	t.GET("/roles/:id", "iam.roles.read", m.handleGetRole)
	t.PATCH("/roles/:id", "iam.roles.manage", m.handleUpdateRole)
	t.DELETE("/roles/:id", "iam.roles.manage", m.handleDeleteRole)

	// Role permissions.
	t.GET("/roles/:id/permissions", "iam.roles.read", m.handleGetRolePermissions)
	t.PUT("/roles/:id/permissions", "iam.roles.manage", m.handleSetRolePermissions)

	// Invitations.
	t.GET("/invitations", "iam.invitations.read", m.handleListInvitations)
	t.POST("/invitations", "iam.invitations.manage", m.handleCreateInvitation)
	t.GET("/invitations/:id", "iam.invitations.read", m.handleGetInvitation)
	t.DELETE("/invitations/:id", "iam.invitations.manage", m.handleRevokeInvitation)

	// Auth providers (per-tenant IdP configuration).
	t.GET("/auth-providers", "iam.tenants.manage", m.handleListAuthProviders)
	t.PUT("/auth-providers", "iam.tenants.manage", m.handleSetAuthProviders)

}
