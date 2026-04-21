package iam_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	iam "github.com/kernel-contrib/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.edgescale.dev/kernel/sdk"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ── test DB setup ─────────────────────────────────────────────────────────────

// newTestDB opens an in-memory SQLite database and creates the IAM tables.
// We use raw DDL instead of AutoMigrate because sdk.BaseModel includes
// `default:gen_random_uuid()` which is PostgreSQL-only. UUIDs are generated
// in Go via BeforeCreate hooks.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "open in-memory sqlite")

	ddl := []string{
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			created_at DATETIME, updated_at DATETIME, deleted_at DATETIME,
			provider TEXT NOT NULL, provider_id TEXT NOT NULL,
			email TEXT, phone TEXT,
			name BLOB NOT NULL DEFAULT '{}',
			password_hash TEXT, avatar_url TEXT,
			locale TEXT NOT NULL DEFAULT 'en',
			timezone TEXT NOT NULL DEFAULT 'UTC',
			status TEXT NOT NULL DEFAULT 'active',
			metadata BLOB, last_login_at DATETIME
		)`,
		`CREATE UNIQUE INDEX idx_users_provider ON users(provider, provider_id)`,
		`CREATE TABLE tenants (
			id TEXT PRIMARY KEY,
			created_at DATETIME, updated_at DATETIME, deleted_at DATETIME,
			parent_id TEXT, slug TEXT NOT NULL, name TEXT NOT NULL,
			type TEXT NOT NULL, path TEXT NOT NULL,
			depth INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			metadata BLOB, logo_url TEXT
		)`,
		`CREATE TABLE tenant_members (
			id TEXT PRIMARY KEY,
			created_at DATETIME, updated_at DATETIME, deleted_at DATETIME,
			user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active'
		)`,
		`CREATE UNIQUE INDEX idx_members_user_tenant ON tenant_members(user_id, tenant_id)`,
		`CREATE TABLE roles (
			id TEXT PRIMARY KEY,
			created_at DATETIME, updated_at DATETIME, deleted_at DATETIME,
			tenant_id TEXT NOT NULL, name TEXT NOT NULL, slug TEXT NOT NULL,
			description TEXT, is_system INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX idx_roles_tenant_slug ON roles(tenant_id, slug)`,
		`CREATE TABLE role_permissions (
			id TEXT PRIMARY KEY,
			role_id TEXT NOT NULL, permission_key TEXT NOT NULL,
			created_at DATETIME
		)`,
		`CREATE TABLE member_roles (
			id TEXT PRIMARY KEY,
			member_id TEXT NOT NULL, role_id TEXT NOT NULL,
			created_at DATETIME
		)`,
		`CREATE UNIQUE INDEX idx_member_roles ON member_roles(member_id, role_id)`,
		`CREATE TABLE invitations (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL, invited_by TEXT NOT NULL,
			email TEXT, phone TEXT, role_id TEXT NOT NULL,
			token_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
			expires_at DATETIME NOT NULL, accepted_at DATETIME,
			created_at DATETIME, updated_at DATETIME
		)`,
	}

	for _, stmt := range ddl {
		require.NoError(t, db.Exec(stmt).Error, "DDL: %s", stmt[:40])
	}
	return db
}

// ── test harness ──────────────────────────────────────────────────────────────

type testHarness struct {
	db      *gorm.DB
	ctx     *sdk.Context
	repo    *iam.Repository
	users   *iam.UserService
	tenants *iam.TenantService
	members *iam.MemberService
	roles   *iam.RoleService
	invites *iam.InvitationService
	onboard *iam.OnboardService
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	db := newTestDB(t)
	tctx := sdk.NewTestContext("iam")
	tctx.DB = db

	repo := iam.NewRepository(db)
	bus := tctx.Bus
	hooks := tctx.Hooks
	log := tctx.Logger

	users := iam.NewUserService(repo, bus, tctx.Redis, log)
	tenants := iam.NewTenantService(repo, bus, hooks, log)
	members := iam.NewMemberService(repo, bus, tctx.Redis, log)
	roles := iam.NewRoleService(repo, bus, tctx.Redis, log, nil)
	invites := iam.NewInvitationService(repo, bus, log)

	// seedSystemRoles needs the Module, but for unit tests we create
	// a simple provision function that delegates to roles.
	seedFn := func(ctx context.Context, tenantID uuid.UUID) (*iam.Role, error) {
		defs := []struct {
			Name, Slug, Desc string
			Perms            []string
		}{
			{"Admin", "admin", "Full access", []string{"*"}},
			{"Manager", "manager", "Manage access", []string{"iam.tenants.read", "iam.members.read"}},
			{"Member", "member", "Basic access", []string{"iam.tenants.read"}},
		}
		var adminRole *iam.Role
		for _, d := range defs {
			desc := d.Desc
			role := &iam.Role{
				TenantID:    tenantID,
				Name:        d.Name,
				Slug:        d.Slug,
				Description: &desc,
				IsSystem:    true,
			}
			if err := repo.CreateRole(ctx, role); err != nil {
				return nil, err
			}
			if err := repo.SetRolePermissions(ctx, role.ID, d.Perms); err != nil {
				return nil, err
			}
			if d.Slug == "admin" {
				adminRole = role
			}
		}
		return adminRole, nil
	}

	onboard := iam.NewOnboardService(users, tenants, members, roles, invites, seedFn, *tctx, log)

	return &testHarness{
		db:      db,
		ctx:     tctx,
		repo:    repo,
		users:   users,
		tenants: tenants,
		members: members,
		roles:   roles,
		invites: invites,
		onboard: onboard,
	}
}

func (h *testHarness) bus() *sdk.TestBus {
	return h.ctx.Bus.(*sdk.TestBus)
}

// createPlatform creates a platform tenant for tests.
func (h *testHarness) createPlatform(t *testing.T) *iam.Tenant {
	t.Helper()
	ctx := context.Background()
	platform := &iam.Tenant{
		Slug: "platform",
		Name: "Platform",
		Type: iam.TenantTypePlatform,
		Path: "/",
	}
	platform.ID = uuid.New()
	require.NoError(t, h.repo.CreateTenant(ctx, platform))
	return platform
}

// createUser creates a test user.
func (h *testHarness) createUser(t *testing.T) *iam.User {
	t.Helper()
	user, err := h.users.Create(context.Background(), iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: uuid.New().String(),
	})
	require.NoError(t, err)
	return user
}

// isNotFound checks if err is a 404 sdk.ServiceError.
func isNotFound(err error) bool {
	se, ok := sdk.IsServiceError(err)
	return ok && se.HTTPStatus == 404
}

func isBadRequest(err error) bool {
	se, ok := sdk.IsServiceError(err)
	return ok && se.HTTPStatus == 400
}

func isConflict(err error) bool {
	se, ok := sdk.IsServiceError(err)
	return ok && se.HTTPStatus == 409
}

func isForbidden(err error) bool {
	se, ok := sdk.IsServiceError(err)
	return ok && se.HTTPStatus == 403
}

// ═══════════════════════════════════════════════════════════════════════════════
// User Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestUserCreate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	email := "test@example.com"
	user, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "fb-123",
		Email:      &email,
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.Equal(t, "firebase", user.Provider)
	assert.Equal(t, "fb-123", user.ProviderID)
	assert.Equal(t, &email, user.Email)
	assert.Equal(t, iam.UserStatusActive, user.Status)

	// Event published.
	events := h.bus().Events()
	require.Len(t, events, 1)
	assert.Equal(t, "iam.user.created", events[0].Subject)
}

func TestUserCreate_DuplicateProvider(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	input := iam.CreateUserInput{Provider: "firebase", ProviderID: "dup-001"}
	_, err := h.users.Create(ctx, input)
	require.NoError(t, err)

	_, err = h.users.Create(ctx, input)
	assert.True(t, isConflict(err), "expected 409, got: %v", err)
}

func TestUserUpdate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	user := h.createUser(t)

	newName := "Jane Doe"
	updated, err := h.users.Update(ctx, user.ID, iam.UpdateUserInput{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "Jane Doe", string(updated.Name))
}

func TestUserSuspend(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	user := h.createUser(t)

	suspended, err := h.users.Suspend(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, iam.UserStatusSuspended, suspended.Status)
}

func TestUserErase(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	email := "gdpr@example.com"
	user, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "gdpr-user",
		Email:      &email,
	})
	require.NoError(t, err)

	err = h.users.Erase(ctx, user.ID)
	require.NoError(t, err)

	erased, err := h.users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, iam.UserStatusErased, erased.Status)
	assert.Nil(t, erased.Email, "email should be nil after erasure")
	assert.Contains(t, erased.ProviderID, "erased:", "provider_id should be hashed")
}

func TestUserGetByID_NotFound(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.users.GetByID(context.Background(), uuid.New())
	assert.True(t, isNotFound(err))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tenant Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestTenantCreateOrg(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug:       "acme-corp",
		Name:       "Acme Corp",
		PlatformID: platform.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, iam.TenantTypeOrganization, org.Type)
	assert.Equal(t, "acme-corp", org.Slug)
	assert.Equal(t, 1, org.Depth)
	assert.Contains(t, org.Path, org.ID.String())
}

func TestTenantCreateBranch(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "acme", Name: "Acme", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	branch, err := h.tenants.CreateBranch(ctx, iam.CreateBranchInput{
		Slug: "branch-a", Name: "Branch A", TenantID: org.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, iam.TenantTypeBranch, branch.Type)
	assert.Equal(t, 2, branch.Depth)
	assert.Contains(t, branch.Path, org.ID.String())
}

func TestTenantMaxDepth(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "deep", Name: "Deep", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	branch, err := h.tenants.CreateBranch(ctx, iam.CreateBranchInput{
		Slug: "br1", Name: "Branch 1", TenantID: org.ID,
	})
	require.NoError(t, err)

	// depth 2 (branch) is the max — creating a child should fail.
	_, err = h.tenants.CreateBranch(ctx, iam.CreateBranchInput{
		Slug: "br2", Name: "Sub Branch", TenantID: branch.ID,
	})
	assert.True(t, isBadRequest(err), "expected 400 for exceeding max depth, got: %v", err)
}

func TestTenantDeactivate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "deactivate-me", Name: "Deact", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	err = h.tenants.Deactivate(ctx, org.ID)
	require.NoError(t, err)

	// Tenant should not be findable after soft-delete.
	_, err = h.tenants.GetByID(ctx, org.ID)
	assert.True(t, isNotFound(err))
}

func TestTenantDeactivate_CascadesChildren(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "cascade", Name: "Cascade Org", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	branch, err := h.tenants.CreateBranch(ctx, iam.CreateBranchInput{
		Slug: "child-branch", Name: "Branch", TenantID: org.ID,
	})
	require.NoError(t, err)

	err = h.tenants.Deactivate(ctx, org.ID)
	require.NoError(t, err)

	_, err = h.tenants.GetByID(ctx, branch.ID)
	assert.True(t, isNotFound(err), "child branch should be deactivated too")
}

func TestTenantDeactivate_PlatformBlocked(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	err := h.tenants.Deactivate(ctx, platform.ID)
	assert.True(t, isBadRequest(err), "platform tenant must not be deactivatable")
}

func TestTenantUpdate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "update-me", Name: "Old Name", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	newName := "New Name"
	updated, err := h.tenants.Update(ctx, org.ID, iam.UpdateTenantInput{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.Name)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Member Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestMemberAdd(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "mem-org", Name: "Mem Org", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	member, err := h.members.Add(ctx, iam.AddMemberInput{
		UserID: user.ID, TenantID: org.ID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, member.ID)
	assert.Equal(t, user.ID, member.UserID)
	assert.Equal(t, org.ID, member.TenantID)
	assert.Equal(t, iam.MemberStatusActive, member.Status)
}

func TestMemberAdd_Duplicate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	org, err := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "dup-mem", Name: "Dup Mem", PlatformID: platform.ID,
	})
	require.NoError(t, err)

	_, err = h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})
	require.NoError(t, err)

	_, err = h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})
	assert.True(t, isConflict(err), "expected 409 for duplicate membership, got: %v", err)
}

func TestMemberRemove(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "rm-mem", Name: "RM Mem", PlatformID: platform.ID,
	})
	member, _ := h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})

	err := h.members.Remove(ctx, member.ID)
	require.NoError(t, err)

	_, err = h.members.GetByID(ctx, member.ID)
	assert.True(t, isNotFound(err))
}

func TestMemberIsMember(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "is-mem", Name: "Is Mem", PlatformID: platform.ID,
	})

	ok, err := h.members.IsMember(ctx, user.ID, org.ID)
	require.NoError(t, err)
	assert.False(t, ok)

	_, _ = h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})

	ok, err = h.members.IsMember(ctx, user.ID, org.ID)
	require.NoError(t, err)
	assert.True(t, ok)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Role Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestRoleCreate(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "role-org", Name: "Role Org", PlatformID: platform.ID,
	})

	role, err := h.roles.Create(ctx, iam.CreateRoleInput{
		TenantID: org.ID, Name: "Editor", Slug: "editor",
	})
	require.NoError(t, err)
	assert.Equal(t, "editor", role.Slug)
	assert.False(t, role.IsSystem)
}

func TestRoleDelete_SystemBlocked(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "sys-role", Name: "Sys Role", PlatformID: platform.ID,
	})

	// Create a system role directly.
	desc := "system"
	role := &iam.Role{TenantID: org.ID, Name: "Admin", Slug: "admin", Description: &desc, IsSystem: true}
	role.ID = uuid.New()
	require.NoError(t, h.repo.CreateRole(ctx, role))

	err := h.roles.Delete(ctx, role.ID)
	assert.True(t, isBadRequest(err), "system roles cannot be deleted, got: %v", err)
}

func TestRoleUpdate_SystemBlocked(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "sys-upd", Name: "Sys Upd", PlatformID: platform.ID,
	})

	desc := "system"
	role := &iam.Role{TenantID: org.ID, Name: "Admin", Slug: "admin", Description: &desc, IsSystem: true}
	role.ID = uuid.New()
	require.NoError(t, h.repo.CreateRole(ctx, role))

	newName := "Renamed"
	_, err := h.roles.Update(ctx, role.ID, iam.UpdateRoleInput{Name: &newName})
	assert.True(t, isBadRequest(err), "system roles cannot be updated, got: %v", err)
}

func TestRoleAssignAndResolve(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "rbac-org", Name: "RBAC", PlatformID: platform.ID,
	})
	member, _ := h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})

	role, _ := h.roles.Create(ctx, iam.CreateRoleInput{
		TenantID: org.ID, Name: "Viewer", Slug: "viewer",
	})
	require.NoError(t, h.roles.SetPermissions(ctx, role.ID, []string{"iam.tenants.read", "iam.members.read"}))
	require.NoError(t, h.roles.AssignToMember(ctx, member.ID, role.ID))

	// Resolve permissions.
	perms, err := h.roles.ResolvePermissions(ctx, user.ID, org.ID)
	require.NoError(t, err)
	assert.Contains(t, perms, "iam.tenants.read")
	assert.Contains(t, perms, "iam.members.read")

	// HasPermission.
	ok, err := h.roles.HasPermission(ctx, user.ID, org.ID, "iam.tenants.read")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = h.roles.HasPermission(ctx, user.ID, org.ID, "iam.roles.manage")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRoleWildcard(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "wildcard", Name: "Wildcard", PlatformID: platform.ID,
	})
	member, _ := h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})

	adminRole, _ := h.roles.Create(ctx, iam.CreateRoleInput{
		TenantID: org.ID, Name: "SuperAdmin", Slug: "superadmin",
	})
	require.NoError(t, h.roles.SetPermissions(ctx, adminRole.ID, []string{"*"}))
	require.NoError(t, h.roles.AssignToMember(ctx, member.ID, adminRole.ID))

	ok, err := h.roles.HasPermission(ctx, user.ID, org.ID, "iam.anything.at_all")
	require.NoError(t, err)
	assert.True(t, ok, "wildcard * should grant all permissions")
}

func TestRoleRevoke(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)
	org, _ := h.tenants.CreateOrg(ctx, iam.CreateOrgInput{
		Slug: "revoke", Name: "Revoke", PlatformID: platform.ID,
	})
	member, _ := h.members.Add(ctx, iam.AddMemberInput{UserID: user.ID, TenantID: org.ID})

	role, _ := h.roles.Create(ctx, iam.CreateRoleInput{
		TenantID: org.ID, Name: "Temp", Slug: "temp",
	})
	require.NoError(t, h.roles.SetPermissions(ctx, role.ID, []string{"iam.tenants.read"}))
	require.NoError(t, h.roles.AssignToMember(ctx, member.ID, role.ID))

	// Revoke.
	require.NoError(t, h.roles.RevokeFromMember(ctx, member.ID, role.ID))

	// Permissions should be empty.
	perms, err := h.roles.ResolvePermissions(ctx, user.ID, org.ID)
	require.NoError(t, err)
	assert.Empty(t, perms)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Onboarding Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestOnboard_NewUser_NewOrg(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	out, err := h.onboard.Execute(ctx, iam.OnboardInput{
		Provider:   "firebase",
		ProviderID: "new-user-1",
		TenantName: "My Company",
		TenantSlug: "my-company",
		PlatformID: platform.ID,
	})
	require.NoError(t, err)
	assert.NotNil(t, out.User)
	assert.NotNil(t, out.Tenant)
	assert.True(t, out.IsNew)
	assert.Equal(t, "my-company", out.Tenant.Slug)
	assert.Equal(t, iam.TenantTypeOrganization, out.Tenant.Type)

	// User should be a member of the new org.
	ok, err := h.members.IsMember(ctx, out.User.ID, out.Tenant.ID)
	require.NoError(t, err)
	assert.True(t, ok, "user should be member of the new org")

	// Admin role should be assigned.
	perms, err := h.roles.ResolvePermissions(ctx, out.User.ID, out.Tenant.ID)
	require.NoError(t, err)
	assert.Contains(t, perms, "*", "founder should have wildcard admin")
}

func TestOnboard_ExistingUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	// First onboard.
	out1, err := h.onboard.Execute(ctx, iam.OnboardInput{
		Provider:   "firebase",
		ProviderID: "repeat-user",
		TenantName: "First Org",
		TenantSlug: "first-org",
		PlatformID: platform.ID,
	})
	require.NoError(t, err)

	// Second onboard with same identity — new org.
	out2, err := h.onboard.Execute(ctx, iam.OnboardInput{
		Provider:   "firebase",
		ProviderID: "repeat-user",
		TenantName: "Second Org",
		TenantSlug: "second-org",
		PlatformID: platform.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, out1.User.ID, out2.User.ID, "same user across onboards")
	assert.NotEqual(t, out1.Tenant.ID, out2.Tenant.ID, "different orgs")
}

func TestOnboard_SuspendedUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	// Create and suspend user.
	user, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider: "firebase", ProviderID: "suspended-guy",
	})
	require.NoError(t, err)
	_, err = h.users.Suspend(ctx, user.ID)
	require.NoError(t, err)

	_, err = h.onboard.Execute(ctx, iam.OnboardInput{
		Provider:   "firebase",
		ProviderID: "suspended-guy",
		TenantName: "Should Fail",
		TenantSlug: "should-fail",
		PlatformID: platform.ID,
	})
	assert.True(t, isForbidden(err), "suspended user should not onboard, got: %v", err)
}

func TestOnboard_MissingSlug(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	_, err := h.onboard.Execute(ctx, iam.OnboardInput{
		Provider:   "firebase",
		ProviderID: "no-slug-user",
		PlatformID: platform.ID,
	})
	assert.True(t, isBadRequest(err), "should require slug/name, got: %v", err)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestTenantTypeChecks(t *testing.T) {
	platform := &iam.Tenant{Type: iam.TenantTypePlatform}
	org := &iam.Tenant{Type: iam.TenantTypeOrganization}
	branch := &iam.Tenant{Type: iam.TenantTypeBranch}

	assert.True(t, platform.IsPlatform())
	assert.False(t, platform.IsOrg())
	assert.True(t, org.IsOrg())
	assert.False(t, org.IsBranch())
	assert.True(t, branch.IsBranch())
	assert.False(t, branch.IsPlatform())
}

func TestTenantMetadata(t *testing.T) {
	tenant := &iam.Tenant{}

	data := map[string]string{"industry": "tech"}
	require.NoError(t, tenant.SetMetadata(data))

	var result map[string]string
	require.NoError(t, tenant.GetMetadata(&result))
	assert.Equal(t, "tech", result["industry"])
}
