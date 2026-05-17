package iam

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	"github.com/google/uuid"
	"github.com/kernel-contrib/iam/migrations"
	"github.com/kernel-contrib/sdk"
)

// Module is the EdgeScale Kernel core module for Identity and Access Management.
// It manages users, tenants (platform → org → branch), memberships, roles,
// permissions, and invitations.

// platformCacheKey is the Redis key used to cache the platform tenant ID.
const platformCacheKey = "platform_tenant_id"

// platformCacheTTL is a safety-net expiry. Under normal operation the cache
// is warmed during provisioning, so this TTL only guards against stale data
// if someone manually edits the DB.
const platformCacheTTL = 24 * time.Hour

type Module struct {
	ctx          sdk.Context
	repo         *Repository
	users        *UserService
	tenants      *TenantService
	members      *MemberService
	roles        *RoleService
	invitations  *InvitationService
	registration *RegistrationService
	client       *iamClient
}

// New constructs the IAM module.
func New() *Module {
	return &Module{}
}

// Manifest returns immutable metadata for the IAM module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "iam",
		Type:        sdk.TypeCore,
		Schema:      "module_iam",
		Name:        "Identity & Access Management",
		Description: "Multi-tenant IAM: users, tenants, memberships, RBAC, and invitations",
		Version:     "1.0.0",

		Permissions: []sdk.Permission{
			// Simplified keys (preferred for new code).
			{Key: PermRead, Label: sdk.T("View IAM resources", "ar", "عرض موارد الهوية"), DefaultRoles: []string{sdk.RoleManager, sdk.RoleMember}},
			{Key: PermWrite, Label: sdk.T("Manage IAM resources", "ar", "إدارة موارد الهوية"), DefaultRoles: []string{sdk.RoleManager}},
			// Legacy keys (kept for 3-5 releases).
			{Key: PermTenantsRead, Label: sdk.T("View tenant details", "ar", "عرض تفاصيل المستأجر"), DefaultRoles: []string{sdk.RoleManager, sdk.RoleMember}},
			{Key: PermTenantsManage, Label: sdk.T("Create, update, and delete tenants", "ar", "إنشاء وتعديل وحذف المستأجرين"), DefaultRoles: []string{sdk.RoleManager}},
			{Key: PermMembersRead, Label: sdk.T("View members", "ar", "عرض الأعضاء"), DefaultRoles: []string{sdk.RoleManager, sdk.RoleMember}},
			{Key: PermMembersManage, Label: sdk.T("Add, update, and remove members", "ar", "إضافة وتعديل وإزالة الأعضاء"), DefaultRoles: []string{sdk.RoleManager}},
			{Key: PermRolesRead, Label: sdk.T("View roles", "ar", "عرض الأدوار"), DefaultRoles: []string{sdk.RoleManager, sdk.RoleMember}},
			{Key: PermRolesManage, Label: sdk.T("Create, update, and delete roles", "ar", "إنشاء وتعديل وحذف الأدوار"), DefaultRoles: []string{sdk.RoleManager}},
			{Key: PermInvitationsRead, Label: sdk.T("View invitations", "ar", "عرض الدعوات"), DefaultRoles: []string{sdk.RoleManager}},
			{Key: PermInvitationsManage, Label: sdk.T("Create and revoke invitations", "ar", "إنشاء وإلغاء الدعوات"), DefaultRoles: []string{sdk.RoleManager}},
			{Key: PermPermissionsRead, Label: sdk.T("View permissions catalog", "ar", "عرض كتالوج الصلاحيات"), DefaultRoles: []string{sdk.RoleManager}},
		},

		PublicEvents: []sdk.EventDef{
			// Users
			{Subject: "iam.user.created", Description: sdk.T("A new user was created")},
			{Subject: "iam.user.updated", Description: sdk.T("A user profile was updated")},
			{Subject: "iam.user.suspended", Description: sdk.T("A user was suspended")},
			{Subject: "iam.user.erased", Description: sdk.T("A user's PII was erased (GDPR)")},
			// Tenants
			{Subject: "iam.tenant.created", Description: sdk.T("A new tenant was created")},
			{Subject: "iam.tenant.updated", Description: sdk.T("A tenant was updated")},
			{Subject: "iam.tenant.deleted", Description: sdk.T("A tenant was deactivated")},
			// Members
			{Subject: "iam.member.added", Description: sdk.T("A member was added to a tenant")},
			{Subject: "iam.member.removed", Description: sdk.T("A member was removed from a tenant")},
			// Roles
			{Subject: "iam.role.created", Description: sdk.T("A role was created")},
			{Subject: "iam.role.updated", Description: sdk.T("A role was updated")},
			{Subject: "iam.role.deleted", Description: sdk.T("A role was deleted")},
			// Invitations
			{Subject: "iam.invitation.created", Description: sdk.T("An invitation was sent")},
			{Subject: "iam.invitation.accepted", Description: sdk.T("An invitation was accepted")},
			// Onboarding
			{Subject: "iam.user.onboarded", Description: sdk.T("A user completed onboarding")},
			// Auth providers
			{Subject: "iam.tenant.auth_config.updated", Description: sdk.T("A tenant's allowed auth providers were updated")},
		},

		Config: []sdk.ConfigFieldDef{
			{
				Key:     "iam.rbac_mode",
				Type:    "select",
				Default: "override",
				Label:   sdk.T("RBAC resolution mode", "ar", "وضع حل الصلاحيات"),
				Description: sdk.T(
					"How permissions are resolved across the tenant hierarchy. 'override' uses the most-specific membership; 'additive' unions permissions from all ancestor memberships.",
					"ar", "كيفية حل الصلاحيات عبر التسلسل الهرمي. 'override' يستخدم العضوية الأكثر تحديدًا؛ 'additive' يجمع الصلاحيات من جميع العضويات.",
				),
				Options: []sdk.ConfigOption{
					{Value: "override", Label: sdk.T("Override (most-specific wins)", "ar", "تجاوز (الأكثر تحديدًا يفوز)")},
					{Value: "additive", Label: sdk.T("Additive (union of all levels)", "ar", "تراكمي (اتحاد جميع المستويات)")},
				},
			},
		},

		UINav: []sdk.NavItem{
			{Label: sdk.T("Members", "ar", "الأعضاء"), Icon: "users", Path: "/iam/members", Permission: PermRead, SortOrder: 1},
			{Label: sdk.T("Roles", "ar", "الأدوار"), Icon: "shield", Path: "/iam/roles", Permission: PermRead, SortOrder: 2},
			{Label: sdk.T("Invitations", "ar", "الدعوات"), Icon: "mail", Path: "/iam/invitations", Permission: PermRead, SortOrder: 3},
		},
	}
}

// Migrations returns the embedded SQL migration files.
func (m *Module) Migrations() fs.FS {
	return migrations.FS
}

// Init wires the module's dependencies. Called once at startup by the kernel.
func (m *Module) Init(ctx sdk.Context) error {
	m.ctx = ctx
	m.repo = NewRepository(ctx.DB)

	// Build services bottom-up.
	m.users = NewUserService(m.repo, ctx.Bus, ctx.Redis, ctx.Logger)
	m.tenants = NewTenantService(m.repo, ctx.Bus, ctx.Hooks, ctx.Logger) // hooks set in RegisterHooks()
	m.members = NewMemberService(m.repo, ctx.Bus, ctx.Redis, ctx.Logger)
	m.roles = NewRoleService(m.repo, ctx.Bus, ctx.Redis, ctx.Logger, ctx.ValidPermissionKey)
	m.invitations = NewInvitationService(m.repo, ctx.Bus, ctx.Logger)
	m.registration = NewRegistrationService(
		m.users, m.tenants, m.members, m.roles, m.invitations,
		m.repo, // used to look up global system roles
		ctx.DB, ctx.Bus, ctx.Redis, ctx.Logger,
	)

	// Construct the unified client first (used by both reader and cross-module consumers).
	m.client = &iamClient{
		users:        m.users,
		tenants:      m.tenants,
		members:      m.members,
		roles:        m.roles,
		invitations:  m.invitations,
		registration: m.registration,
		repo:         m.repo,
		redis:        ctx.Redis,
		audit:        ctx.Audit,
		db:           ctx.DB,
	}

	// Register the reader for cross-module consumption (legacy).
	// Other modules resolve reads via: sdk.Reader[iam.IAMReader](&m.ctx, "iam")
	// Other modules resolve writes via: sdk.Reader[iam.IAMRegistrar](&m.ctx, "iam")
	ctx.RegisterReader(&iamReader{
		iamRegistrar: &iamRegistrar{registration: m.registration},
		iamClient:    m.client,
	})

	// Register the unified client for new cross-module consumers.
	// Resolved via: sdk.Client[iam.IAMClient](&m.ctx, "iam")
	ctx.RegisterClient(m.client)

	// Reconcile global system role permissions with the latest module
	// manifests. This ensures new permissions from newly deployed modules
	// are added, and stale permissions from removed modules are pruned.
	// Touches only 3 role rows regardless of tenant count.
	if err := m.reconcileSystemRoles(context.Background()); err != nil {
		return fmt.Errorf("iam: reconcile system roles: %w", err)
	}

	ctx.Logger.Info("iam module initialized")
	return nil
}

// Shutdown performs any cleanup required before the kernel stops.
func (m *Module) Shutdown() error {
	return nil
}

// platformTenantID lazily resolves the platform tenant's UUID.
//
// Resolution order:
//  1. Redis cache (module:iam:platform_tenant_id).
//  2. Database query (SELECT ... WHERE type = 'platform' LIMIT 1).
//
// On a cache miss the result is stored in Redis with platformCacheTTL.
// Returns a clear error if no platform tenant has been created yet.
func (m *Module) platformTenantID(ctx context.Context) (uuid.UUID, error) {
	// 1. Try Redis.
	if m.ctx.Redis.Client() != nil {
		if val, err := m.ctx.Redis.Get(ctx, platformCacheKey).Result(); err == nil {
			id, parseErr := uuid.Parse(val)
			if parseErr == nil {
				return id, nil
			}
		}
	}

	// 2. Query the database.
	platform, err := m.repo.FindPlatformTenant(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("iam: platform tenant not found; create one with type='platform' and run 'tenant provision': %w", err)
	}

	// 3. Warm the cache for subsequent requests.
	if m.ctx.Redis.Client() != nil {
		m.ctx.Redis.Set(ctx, platformCacheKey, platform.ID.String(), platformCacheTTL)
	}

	return platform.ID, nil
}

// ResolvePlatformTenantID satisfies sdk.PlatformTenantResolver.
// This allows the consumer to pass the IAM module directly to
// kernel.SetPlatformTenantResolver(iamModule).
func (m *Module) ResolvePlatformTenantID(ctx context.Context) (uuid.UUID, error) {
	return m.platformTenantID(ctx)
}

// ResolveUser satisfies sdk.UserResolver. It resolves an external identity
// into a tenant-scoped internal user with permissions.
//
// When tenantID is uuid.Nil, it performs identity-only resolution: returns the
// internal user UUID without checking membership or resolving permissions.
// This is used by global (non-tenant) routes to identify the caller.
func (m *Module) ResolveUser(ctx context.Context, provider, externalID string, tenantID uuid.UUID) (*sdk.ResolvedUser, error) {
	user, err := m.repo.FindUserByProviderID(ctx, externalID, provider)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, err
	}

	// Identity-only resolution: no tenant context, no membership or
	// permission checks. Used for global authenticated routes.
	if tenantID == uuid.Nil {
		return &sdk.ResolvedUser{InternalID: user.ID}, nil
	}

	// Verify membership in this tenant (or its ancestor chain).
	member, err := m.members.IsMemberAnywhere(ctx, user.ID, tenantID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		return nil, nil
	}

	perms, err := m.client.ResolvePermissions(ctx, user.ID, tenantID)
	if err != nil {
		return nil, err
	}

	return &sdk.ResolvedUser{
		InternalID:  user.ID,
		MemberID:    member.ID,
		Permissions: perms,
	}, nil
}

// ResolveAdmin satisfies sdk.AdminResolver. It resolves an external identity
// into a platform-level admin with permissions.
func (m *Module) ResolveAdmin(ctx context.Context, provider, externalID string) (*sdk.ResolvedUser, error) {
	user, err := m.repo.FindUserByProviderID(ctx, externalID, provider)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, err
	}

	platformID, err := m.platformTenantID(ctx)
	if err != nil {
		return nil, err
	}

	perms, err := m.roles.ResolvePermissions(ctx, user.ID, platformID)
	if err != nil {
		return nil, err
	}

	return &sdk.ResolvedUser{
		InternalID:  user.ID,
		Permissions: perms,
	}, nil
}
