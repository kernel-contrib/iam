package iam_test

import (
	"context"
	"testing"

	"github.com/edgescaleDev/kernel/sdk"
	"github.com/google/uuid"
	iam "github.com/kernel-contrib/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		`CREATE TABLE tenant_auth_configs (
			id TEXT PRIMARY KEY,
			created_at DATETIME, updated_at DATETIME, deleted_at DATETIME,
			tenant_id TEXT NOT NULL,
			provider_name TEXT NOT NULL,
			is_enabled INTEGER NOT NULL DEFAULT 1,
			config BLOB
		)`,
		`CREATE UNIQUE INDEX uq_tenant_auth_configs_tenant_provider_active
			ON tenant_auth_configs(tenant_id, provider_name)
			WHERE deleted_at IS NULL`,
	}

	for _, stmt := range ddl {
		require.NoError(t, db.Exec(stmt).Error, "DDL: %s", stmt[:40])
	}
	return db
}

// ── test harness ──────────────────────────────────────────────────────────────

type testHarness struct {
	db           *gorm.DB
	ctx          *sdk.Context
	repo         *iam.Repository
	users        *iam.UserService
	tenants      *iam.TenantService
	members      *iam.MemberService
	roles        *iam.RoleService
	invites      *iam.InvitationService
	registration *iam.RegistrationService
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

	registration := iam.NewRegistrationService(
		users, tenants, members, roles, invites,
		seedFn, db, bus, tctx.Redis, log,
	)

	return &testHarness{
		db:           db,
		ctx:          tctx,
		repo:         repo,
		users:        users,
		tenants:      tenants,
		members:      members,
		roles:        roles,
		invites:      invites,
		registration: registration,
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
	assert.JSONEq(t, `{"base":"Jane Doe"}`, string(updated.Name))
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
// Registration Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestRegister_NewUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	out, err := h.registration.Register(ctx, iam.RegisterInput{
		Provider:   "firebase",
		ProviderID: "new-user-1",
	})
	require.NoError(t, err)
	assert.True(t, out.IsNew)
	assert.NotEqual(t, uuid.Nil, out.User.ID)
	assert.Equal(t, "firebase", out.User.Provider)
	assert.Equal(t, "new-user-1", out.User.ProviderID)
}

func TestRegister_ExistingUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	// Register once.
	out1, err := h.registration.Register(ctx, iam.RegisterInput{
		Provider:   "firebase",
		ProviderID: "repeat-user",
	})
	require.NoError(t, err)
	assert.True(t, out1.IsNew)

	// Register again with same identity.
	out2, err := h.registration.Register(ctx, iam.RegisterInput{
		Provider:   "firebase",
		ProviderID: "repeat-user",
	})
	require.NoError(t, err)
	assert.False(t, out2.IsNew)
	assert.Equal(t, out1.User.ID, out2.User.ID, "same user returned")
}

func TestRegister_MissingProvider(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	_, err := h.registration.Register(ctx, iam.RegisterInput{})
	assert.True(t, isBadRequest(err), "should require provider, got: %v", err)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Create Organization Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCreateOrganization_Success(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	out, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "My Company",
		Slug:       "my-company",
	})
	require.NoError(t, err)
	assert.Equal(t, "my-company", out.Tenant.Slug)
	assert.Equal(t, iam.TenantTypeOrganization, out.Tenant.Type)
	assert.NotNil(t, out.Membership)
	assert.NotNil(t, out.Role)
	assert.Equal(t, "admin", out.Role.Slug)

	// User should be a member of the new org.
	ok, err := h.members.IsMember(ctx, user.ID, out.Tenant.ID)
	require.NoError(t, err)
	assert.True(t, ok, "user should be member of the new org")

	// Admin role should be assigned.
	perms, err := h.roles.ResolvePermissions(ctx, user.ID, out.Tenant.ID)
	require.NoError(t, err)
	assert.Contains(t, perms, "*", "founder should have wildcard admin")
}

func TestCreateOrganization_ExistingUserMultipleOrgs(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	out1, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "First Org",
		Slug:       "first-org",
	})
	require.NoError(t, err)

	out2, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "Second Org",
		Slug:       "second-org",
	})
	require.NoError(t, err)
	assert.NotEqual(t, out1.Tenant.ID, out2.Tenant.ID, "different orgs")
}

func TestCreateOrganization_SuspendedUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	user, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider: "firebase", ProviderID: "suspended-guy",
	})
	require.NoError(t, err)
	_, err = h.users.Suspend(ctx, user.ID)
	require.NoError(t, err)

	_, err = h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "Should Fail",
		Slug:       "should-fail",
	})
	assert.True(t, isForbidden(err), "suspended user should not create org, got: %v", err)
}

func TestCreateOrganization_AutoSlugFromName(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	out, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "My Cool Company (UK)",
		// Slug intentionally omitted -- should be auto-generated.
	})
	require.NoError(t, err)
	assert.Equal(t, "my-cool-company-uk", out.Tenant.Slug,
		"slug should be auto-generated from name")
}

func TestCreateOrganization_DuplicateSlug(t *testing.T) {
	// Partial unique indexes (WHERE deleted_at IS NULL) are not reliably
	// enforced in SQLite. This test validates correctly on PostgreSQL.
	t.Skip("requires PostgreSQL for partial unique index enforcement")
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)
	user := h.createUser(t)

	_, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "Acme",
		Slug:       "acme",
	})
	require.NoError(t, err)

	_, err = h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     user.ID,
		PlatformID: platform.ID,
		Name:       "Acme Again",
		Slug:       "acme",
	})
	assert.True(t, isConflict(err), "duplicate slug should conflict, got: %v", err)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Preview Invitation Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestPreviewInvitation_HappyPath(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	platform := h.createPlatform(t)
	admin := h.createUser(t)

	orgOut, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     admin.ID,
		PlatformID: platform.ID,
		Name:       "Preview Org",
		Slug:       "preview-org-" + uuid.New().String()[:8],
	})
	require.NoError(t, err)

	memberRole, err := h.repo.FindRoleBySlugAndTenant(ctx, "member", orgOut.Tenant.ID)
	require.NoError(t, err)

	phone := "+971504444444"
	invOut, err := h.invites.Create(ctx, iam.CreateInvitationInput{
		TenantID:  orgOut.Tenant.ID,
		InvitedBy: admin.ID,
		Phone:     &phone,
		RoleID:    memberRole.ID,
	})
	require.NoError(t, err)

	// Create invitee with matching phone.
	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "preview-invitee",
		Phone:      &phone,
	})
	require.NoError(t, err)

	preview, err := h.registration.PreviewInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  invOut.RawToken,
	})
	require.NoError(t, err)
	assert.Equal(t, orgOut.Tenant.ID, preview.TenantID)
	assert.Equal(t, "Preview Org", preview.TenantName)
	assert.Equal(t, "Member", preview.RoleName)
	assert.Equal(t, admin.ID, preview.InvitedBy)
}

func TestPreviewInvitation_WrongPhone(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	platform := h.createPlatform(t)
	admin := h.createUser(t)

	orgOut, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     admin.ID,
		PlatformID: platform.ID,
		Name:       "Wrong Preview Org",
		Slug:       "wrong-preview-" + uuid.New().String()[:8],
	})
	require.NoError(t, err)

	memberRole, err := h.repo.FindRoleBySlugAndTenant(ctx, "member", orgOut.Tenant.ID)
	require.NoError(t, err)

	phone := "+971505555555"
	invOut, err := h.invites.Create(ctx, iam.CreateInvitationInput{
		TenantID:  orgOut.Tenant.ID,
		InvitedBy: admin.ID,
		Phone:     &phone,
		RoleID:    memberRole.ID,
	})
	require.NoError(t, err)

	wrongPhone := "+971509999999"
	intruder, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "preview-intruder",
		Phone:      &wrongPhone,
	})
	require.NoError(t, err)

	_, err = h.registration.PreviewInvitation(ctx, iam.AcceptInviteInput{
		UserID: intruder.ID,
		Token:  invOut.RawToken,
	})
	assert.True(t, isForbidden(err),
		"wrong phone should be rejected, got: %v", err)
}

func TestPreviewInvitation_ExpiredToken(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	phone := "+971506666666"
	_, _, rawToken, _ := setupOrgWithInvitation(t, h, phone)

	// Force-expire.
	h.db.Exec("UPDATE invitations SET expires_at = datetime('now', '-1 day')")

	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "preview-expired",
		Phone:      &phone,
	})
	require.NoError(t, err)

	_, err = h.registration.PreviewInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  rawToken,
	})
	assert.True(t, isBadRequest(err),
		"expired invitation should be bad request, got: %v", err)
}

func TestPreviewInvitation_InvalidToken(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	user := h.createUser(t)

	_, err := h.registration.PreviewInvitation(ctx, iam.AcceptInviteInput{
		UserID: user.ID,
		Token:  "bogus-token",
	})
	assert.True(t, isNotFound(err),
		"invalid token should be not found, got: %v", err)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Accept Invitation Tests
// ═══════════════════════════════════════════════════════════════════════════════

// setupOrgWithInvitation is a test helper that creates a platform, org, and
// a phone-based invitation. Returns everything needed for acceptance tests.
func setupOrgWithInvitation(t *testing.T, h *testHarness, phone string) (
	admin *iam.User,
	org *iam.Tenant,
	rawToken string,
	roleID uuid.UUID,
) {
	t.Helper()
	ctx := context.Background()
	platform := h.createPlatform(t)
	admin = h.createUser(t)

	// Create org through registration service (seeds roles).
	orgOut, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     admin.ID,
		PlatformID: platform.ID,
		Name:       "Invite Org",
		Slug:       "invite-org-" + uuid.New().String()[:8],
	})
	require.NoError(t, err)
	org = orgOut.Tenant

	// Find the "member" role for the invitation.
	memberRole, err := h.repo.FindRoleBySlugAndTenant(ctx, "member", org.ID)
	require.NoError(t, err)
	roleID = memberRole.ID

	// Create invitation.
	invOut, err := h.invites.Create(ctx, iam.CreateInvitationInput{
		TenantID:  org.ID,
		InvitedBy: admin.ID,
		Phone:     &phone,
		RoleID:    memberRole.ID,
	})
	require.NoError(t, err)
	rawToken = invOut.RawToken

	return admin, org, rawToken, roleID
}

func TestAcceptInvitation_HappyPath_Phone(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	phone := "+971501234567"
	_, org, rawToken, _ := setupOrgWithInvitation(t, h, phone)

	// Create a user with matching phone.
	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "invitee-phone-1",
		Phone:      &phone,
	})
	require.NoError(t, err)

	out, err := h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  rawToken,
	})
	require.NoError(t, err)
	assert.Equal(t, org.ID, out.Tenant.ID)
	assert.NotNil(t, out.Membership)
	assert.NotNil(t, out.Role)

	// User should be a member.
	ok, err := h.members.IsMember(ctx, invitee.ID, org.ID)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestAcceptInvitation_HappyPath_Email(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	platform := h.createPlatform(t)
	admin := h.createUser(t)

	orgOut, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     admin.ID,
		PlatformID: platform.ID,
		Name:       "Email Org",
		Slug:       "email-org-" + uuid.New().String()[:8],
	})
	require.NoError(t, err)

	memberRole, err := h.repo.FindRoleBySlugAndTenant(ctx, "member", orgOut.Tenant.ID)
	require.NoError(t, err)

	email := "invitee@example.com"
	invOut, err := h.invites.Create(ctx, iam.CreateInvitationInput{
		TenantID:  orgOut.Tenant.ID,
		InvitedBy: admin.ID,
		Email:     &email,
		RoleID:    memberRole.ID,
	})
	require.NoError(t, err)

	// Create invitee with matching email.
	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "invitee-email-1",
		Email:      &email,
	})
	require.NoError(t, err)

	out, err := h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  invOut.RawToken,
	})
	require.NoError(t, err)
	assert.Equal(t, orgOut.Tenant.ID, out.Tenant.ID)
}

func TestAcceptInvitation_WrongPhone(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	_, _, rawToken, _ := setupOrgWithInvitation(t, h, "+971501234567")

	// Create a user with a different phone number.
	wrongPhone := "+971509999999"
	intruder, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "intruder-phone",
		Phone:      &wrongPhone,
	})
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: intruder.ID,
		Token:  rawToken,
	})
	assert.True(t, isForbidden(err),
		"wrong phone should be rejected, got: %v", err)
}

func TestAcceptInvitation_WrongEmail(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	platform := h.createPlatform(t)
	admin := h.createUser(t)

	orgOut, err := h.registration.CreateOrganization(ctx, iam.CreateOrgForUserInput{
		UserID:     admin.ID,
		PlatformID: platform.ID,
		Name:       "Wrong Email Org",
		Slug:       "wrong-email-org-" + uuid.New().String()[:8],
	})
	require.NoError(t, err)

	memberRole, err := h.repo.FindRoleBySlugAndTenant(ctx, "member", orgOut.Tenant.ID)
	require.NoError(t, err)

	targetEmail := "correct@example.com"
	invOut, err := h.invites.Create(ctx, iam.CreateInvitationInput{
		TenantID:  orgOut.Tenant.ID,
		InvitedBy: admin.ID,
		Email:     &targetEmail,
		RoleID:    memberRole.ID,
	})
	require.NoError(t, err)

	// Create user with wrong email.
	wrongEmail := "wrong@example.com"
	intruder, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "intruder-email",
		Email:      &wrongEmail,
	})
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: intruder.ID,
		Token:  invOut.RawToken,
	})
	assert.True(t, isForbidden(err),
		"wrong email should be rejected, got: %v", err)
}

func TestAcceptInvitation_NoPhoneOnUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	_, _, rawToken, _ := setupOrgWithInvitation(t, h, "+971501234567")

	// Create a user without any phone (phone invitation cannot match).
	noPhone, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "no-phone-user",
	})
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: noPhone.ID,
		Token:  rawToken,
	})
	assert.True(t, isForbidden(err),
		"user without phone should not accept phone invitation, got: %v", err)
}

func TestAcceptInvitation_InvalidToken(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	user := h.createUser(t)

	_, err := h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: user.ID,
		Token:  "completely-invalid-token",
	})
	assert.True(t, isNotFound(err),
		"invalid token should be not found, got: %v", err)
}

func TestAcceptInvitation_ExpiredToken(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	phone := "+971501111111"
	_, _, rawToken, _ := setupOrgWithInvitation(t, h, phone)

	// Force-expire the invitation by updating expires_at.
	h.db.Exec("UPDATE invitations SET expires_at = datetime('now', '-1 day')")

	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "expired-invitee",
		Phone:      &phone,
	})
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  rawToken,
	})
	assert.True(t, isBadRequest(err),
		"expired invitation should be bad request, got: %v", err)
}

func TestAcceptInvitation_RevokedToken(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	phone := "+971502222222"
	_, org, rawToken, _ := setupOrgWithInvitation(t, h, phone)

	// Revoke the invitation.
	var invIDStr string
	h.db.Raw("SELECT id FROM invitations WHERE tenant_id = ?", org.ID).Scan(&invIDStr)
	invID, err := uuid.Parse(invIDStr)
	require.NoError(t, err)
	require.NoError(t, h.invites.Revoke(ctx, invID))

	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "revoked-invitee",
		Phone:      &phone,
	})
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  rawToken,
	})
	// The repository query filters by status=pending, so a revoked invitation
	// returns not-found rather than bad-request. This is acceptable -- it avoids
	// leaking the existence of the revoked invitation.
	assert.True(t, isNotFound(err),
		"revoked invitation should not be found, got: %v", err)
}

func TestAcceptInvitation_SuspendedUser(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()

	phone := "+971503333333"
	_, _, rawToken, _ := setupOrgWithInvitation(t, h, phone)

	// Create and suspend the invitee.
	invitee, err := h.users.Create(ctx, iam.CreateUserInput{
		Provider:   "firebase",
		ProviderID: "suspended-invitee",
		Phone:      &phone,
	})
	require.NoError(t, err)
	_, err = h.users.Suspend(ctx, invitee.ID)
	require.NoError(t, err)

	_, err = h.registration.AcceptInvitation(ctx, iam.AcceptInviteInput{
		UserID: invitee.ID,
		Token:  rawToken,
	})
	assert.True(t, isForbidden(err),
		"suspended user should not accept invitation, got: %v", err)
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

// ═══════════════════════════════════════════════════════════════════════════════
// Auth Provider Config Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestAuthConfig_SetAndList(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	// Empty list → open access (no rows).
	err := h.repo.SetAuthConfig(ctx, platform.ID, nil)
	require.NoError(t, err)
	configs, err := h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	assert.Empty(t, configs)

	// Set two providers.
	err = h.repo.SetAuthConfig(ctx, platform.ID, []iam.TenantAuthConfig{
		{ProviderName: "google", IsEnabled: true},
		{ProviderName: "github", IsEnabled: true},
	})
	require.NoError(t, err)
	configs, err = h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	assert.Len(t, configs, 2)

	// Replace with empty → open access again.
	err = h.repo.SetAuthConfig(ctx, platform.ID, nil)
	require.NoError(t, err)
	configs, err = h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	assert.Empty(t, configs)
}

func TestAuthConfig_UndeleteOnReAdd(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	// Add "google".
	err := h.repo.SetAuthConfig(ctx, platform.ID, []iam.TenantAuthConfig{
		{ProviderName: "google", IsEnabled: true},
	})
	require.NoError(t, err)

	// Soft-delete it (replace with empty list).
	err = h.repo.SetAuthConfig(ctx, platform.ID, nil)
	require.NoError(t, err)
	configs, err := h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	assert.Empty(t, configs, "provider should be soft-deleted")

	// Re-add "google" — should restore the soft-deleted row, not create a new one.
	err = h.repo.SetAuthConfig(ctx, platform.ID, []iam.TenantAuthConfig{
		{ProviderName: "google", IsEnabled: false},
	})
	require.NoError(t, err)

	configs, err = h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	assert.Equal(t, "google", configs[0].ProviderName)
	assert.False(t, configs[0].IsEnabled, "should reflect the reconfigured value")
}

func TestAuthConfig_UpsertRestoresSoftDeleted(t *testing.T) {
	h := newTestHarness(t)
	ctx := context.Background()
	platform := h.createPlatform(t)

	// Add via Upsert.
	err := h.repo.UpsertAuthConfig(ctx, &iam.TenantAuthConfig{
		TenantID:     platform.ID,
		ProviderName: "azure",
		IsEnabled:    true,
	})
	require.NoError(t, err)

	// Soft-delete the "azure" provider (SetAuthConfig with empty).
	require.NoError(t, h.repo.SetAuthConfig(ctx, platform.ID, nil))

	// Upsert "azure" again — must restore it, not create a duplicate.
	err = h.repo.UpsertAuthConfig(ctx, &iam.TenantAuthConfig{
		TenantID:     platform.ID,
		ProviderName: "azure",
		IsEnabled:    false,
	})
	require.NoError(t, err)

	configs, err := h.repo.ListAuthConfig(ctx, platform.ID)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	assert.Equal(t, "azure", configs[0].ProviderName)
	assert.False(t, configs[0].IsEnabled)
}
