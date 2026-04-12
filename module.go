package iam

import (
	"io/fs"

	"go.edgescale.dev/kernel-contrib/iam/migrations"
	"go.edgescale.dev/kernel/sdk"
)

// Module is the EdgeScale Kernel core module for Identity and Access Management.
// It manages users, tenants (platform → org → branch), memberships, roles,
// permissions, and invitations.
type Module struct {
	ctx         sdk.Context
	repo        *Repository
	users       *UserService
	tenants     *TenantService
	members     *MemberService
	roles       *RoleService
	invitations *InvitationService
	onboard     *OnboardService
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
			// Tenants
			{Key: "iam.tenants.read", Label: sdk.T("View tenant details", "ar", "عرض تفاصيل المستأجر")},
			{Key: "iam.tenants.manage", Label: sdk.T("Create, update, and delete tenants", "ar", "إنشاء وتعديل وحذف المستأجرين")},
			// Members
			{Key: "iam.members.read", Label: sdk.T("View members", "ar", "عرض الأعضاء")},
			{Key: "iam.members.manage", Label: sdk.T("Add, update, and remove members", "ar", "إضافة وتعديل وإزالة الأعضاء")},
			// Roles
			{Key: "iam.roles.read", Label: sdk.T("View roles", "ar", "عرض الأدوار")},
			{Key: "iam.roles.manage", Label: sdk.T("Create, update, and delete roles", "ar", "إنشاء وتعديل وحذف الأدوار")},
			// Invitations
			{Key: "iam.invitations.read", Label: sdk.T("View invitations", "ar", "عرض الدعوات")},
			{Key: "iam.invitations.manage", Label: sdk.T("Create and revoke invitations", "ar", "إنشاء وإلغاء الدعوات")},
			// Permissions catalog
			{Key: "iam.permissions.read", Label: sdk.T("View permissions catalog", "ar", "عرض كتالوج الصلاحيات")},
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
			{Label: sdk.T("Members", "ar", "الأعضاء"), Icon: "users", Path: "/iam/members", Permission: "iam.members.read", SortOrder: 1},
			{Label: sdk.T("Roles", "ar", "الأدوار"), Icon: "shield", Path: "/iam/roles", Permission: "iam.roles.read", SortOrder: 2},
			{Label: sdk.T("Invitations", "ar", "الدعوات"), Icon: "mail", Path: "/iam/invitations", Permission: "iam.invitations.read", SortOrder: 3},
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
	m.users = NewUserService(m.repo, ctx.Bus, ctx.Logger)
	m.tenants = NewTenantService(m.repo, ctx.Bus, ctx.Logger)
	m.members = NewMemberService(m.repo, ctx.Bus, ctx.Logger)
	m.roles = NewRoleService(m.repo, ctx.Bus, ctx.Logger, ctx.ValidPermissionKey)
	m.invitations = NewInvitationService(m.repo, ctx.Bus, ctx.Logger)
	m.onboard = NewOnboardService(
		m.users, m.tenants, m.members, m.roles, m.invitations,
		ctx, ctx.Logger,
	)

	ctx.Logger.Info("iam module initialized")
	return nil
}

// Shutdown performs any cleanup required before the kernel stops.
func (m *Module) Shutdown() error {
	return nil
}
