package iam

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel-contrib/iam/types"
	"go.edgescale.dev/kernel/sdk"
	"gorm.io/gorm"
)

// Repository is the data-access layer for the IAM module.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a Repository backed by the provided *gorm.DB.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (r *Repository) FindUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&u).Error; err != nil {
		return nil, fmt.Errorf("iam: find user by id: %w", err)
	}
	return &u, nil
}

func (r *Repository) FindUserByProviderID(ctx context.Context, providerID, provider string) (*User, error) {
	var u User
	if err := r.db.WithContext(ctx).
		Where("provider_id = ? AND provider = ?", providerID, provider).
		First(&u).Error; err != nil {
		return nil, fmt.Errorf("iam: find user by external id: %w", err)
	}
	return &u, nil
}

func (r *Repository) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&u).Error; err != nil {
		return nil, fmt.Errorf("iam: find user by email: %w", err)
	}
	return &u, nil
}

func (r *Repository) FindUserByPhone(ctx context.Context, phone string) (*User, error) {
	var u User
	if err := r.db.WithContext(ctx).Where("phone = ?", phone).First(&u).Error; err != nil {
		return nil, fmt.Errorf("iam: find user by phone: %w", err)
	}
	return &u, nil
}

func (r *Repository) CreateUser(ctx context.Context, u *User) error {
	if err := r.db.WithContext(ctx).Create(u).Error; err != nil {
		return fmt.Errorf("iam: create user: %w", err)
	}
	return nil
}

func (r *Repository) UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]any) (*User, error) {
	if err := r.db.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("iam: update user: %w", err)
	}
	return r.FindUserByID(ctx, id)
}

func (r *Repository) SoftDeleteUser(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&User{}).Error; err != nil {
		return fmt.Errorf("iam: delete user: %w", err)
	}
	return nil
}

// ── Tenants ───────────────────────────────────────────────────────────────────

func (r *Repository) FindTenantByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	var t Tenant
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&t).Error; err != nil {
		return nil, fmt.Errorf("iam: find tenant: %w", err)
	}
	return &t, nil
}

func (r *Repository) FindTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	var t Tenant
	if err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&t).Error; err != nil {
		return nil, fmt.Errorf("iam: find tenant by slug: %w", err)
	}
	return &t, nil
}

func (r *Repository) FindTenantChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error) {
	var children []Tenant
	if err := r.db.WithContext(ctx).
		Where("parent_id = ?", parentID).
		Find(&children).Error; err != nil {
		return nil, fmt.Errorf("iam: find tenant children: %w", err)
	}
	return children, nil
}

// FindTenantAncestors returns all ancestors of a tenant by querying the
// materialized path. The path column stores slash-separated UUIDs from
// root to the current tenant, e.g. "/{platform_id}/{org_id}/{branch_id}".
func (r *Repository) FindTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error) {
	tenant, err := r.FindTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Parse ancestor IDs from the materialized path.
	ancestorIDs := parsePath(tenant.Path)
	if len(ancestorIDs) == 0 {
		return nil, nil
	}

	var ancestors []Tenant
	if err := r.db.WithContext(ctx).
		Where("id IN ?", ancestorIDs).
		Order("depth ASC").
		Find(&ancestors).Error; err != nil {
		return nil, fmt.Errorf("iam: find tenant ancestors: %w", err)
	}
	return ancestors, nil
}

func (r *Repository) CreateTenant(ctx context.Context, t *Tenant) error {
	if err := r.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("iam: create tenant: %w", err)
	}
	return nil
}

func (r *Repository) UpdateTenant(ctx context.Context, id uuid.UUID, updates map[string]any) (*Tenant, error) {
	if err := r.db.WithContext(ctx).
		Model(&Tenant{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("iam: update tenant: %w", err)
	}
	return r.FindTenantByID(ctx, id)
}

func (r *Repository) SoftDeleteTenant(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Tenant{}).Error; err != nil {
		return fmt.Errorf("iam: delete tenant: %w", err)
	}
	return nil
}

// FindOrgForTenant walks up the hierarchy to find the nearest organization
// ancestor. If the tenant itself is an org, it is returned directly.
func (r *Repository) FindOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	tenant, err := r.FindTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant.IsOrg() {
		return tenant, nil
	}

	ancestors, err := r.FindTenantAncestors(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Walk from deepest to shallowest to find nearest org.
	for i := len(ancestors) - 1; i >= 0; i-- {
		if ancestors[i].IsOrg() {
			return &ancestors[i], nil
		}
	}
	return nil, fmt.Errorf("iam: no organization ancestor found for tenant %s", tenantID)
}

// ── Tenant Members ────────────────────────────────────────────────────────────

func (r *Repository) FindMember(ctx context.Context, id uuid.UUID) (*TenantMember, error) {
	var m TenantMember
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error; err != nil {
		return nil, fmt.Errorf("iam: find member: %w", err)
	}
	return &m, nil
}

func (r *Repository) FindMemberByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	var m TenantMember
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		First(&m).Error; err != nil {
		return nil, fmt.Errorf("iam: find member by user and tenant: %w", err)
	}
	return &m, nil
}

func (r *Repository) ListMembers(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[TenantMember], error) {
	return sdk.Paginate[TenantMember](
		r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Preload("User"),
		page,
	)
}

func (r *Repository) CreateMember(ctx context.Context, m *TenantMember) error {
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return fmt.Errorf("iam: create member: %w", err)
	}
	return nil
}

func (r *Repository) UpdateMember(ctx context.Context, id uuid.UUID, updates map[string]any) (*TenantMember, error) {
	if err := r.db.WithContext(ctx).
		Model(&TenantMember{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("iam: update member: %w", err)
	}
	return r.FindMember(ctx, id)
}

func (r *Repository) DeleteMember(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&TenantMember{}).Error; err != nil {
		return fmt.Errorf("iam: delete member: %w", err)
	}
	return nil
}

// FindMemberInAncestorChain looks for a membership for the given user
// in the tenant or any of its ancestors. Returns the most-specific
// (deepest) membership found, or gorm.ErrRecordNotFound if none.
func (r *Repository) FindMemberInAncestorChain(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	tenant, err := r.FindTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Collect all tenant IDs in the chain: self + ancestors.
	chainIDs := append(parsePath(tenant.Path), tenantID)

	var members []TenantMember
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id IN ?", userID, chainIDs).
		Joins("JOIN tenants ON tenants.id = tenant_members.tenant_id").
		Order("tenants.depth DESC").
		Find(&members).Error; err != nil {
		return nil, fmt.Errorf("iam: find member in ancestor chain: %w", err)
	}
	if len(members) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &members[0], nil
}

// ── Roles ─────────────────────────────────────────────────────────────────────

func (r *Repository) FindRoleByID(ctx context.Context, id uuid.UUID) (*Role, error) {
	var role Role
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		return nil, fmt.Errorf("iam: find role: %w", err)
	}
	return &role, nil
}

func (r *Repository) FindRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	var roles []Role
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Preload("Permissions").
		Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("iam: find roles by tenant: %w", err)
	}
	return roles, nil
}

func (r *Repository) FindSystemRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	var roles []Role
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND is_system = ?", tenantID, true).
		Preload("Permissions").
		Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("iam: find system roles: %w", err)
	}
	return roles, nil
}

func (r *Repository) CreateRole(ctx context.Context, role *Role) error {
	if err := r.db.WithContext(ctx).Create(role).Error; err != nil {
		return fmt.Errorf("iam: create role: %w", err)
	}
	return nil
}

func (r *Repository) UpdateRole(ctx context.Context, id uuid.UUID, updates map[string]any) (*Role, error) {
	if err := r.db.WithContext(ctx).
		Model(&Role{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("iam: update role: %w", err)
	}
	return r.FindRoleByID(ctx, id)
}

func (r *Repository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	if err := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Role{}).Error; err != nil {
		return fmt.Errorf("iam: delete role: %w", err)
	}
	return nil
}

// ── Role Permissions ──────────────────────────────────────────────────────────

// SetRolePermissions replaces all permissions for a role.
// Uses insert-first-then-delete-stale to avoid gaps.
func (r *Repository) SetRolePermissions(ctx context.Context, roleID uuid.UUID, keys []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Insert new permissions (ignore conflicts on existing).
		for _, key := range keys {
			rp := RolePermission{RoleID: roleID, PermissionKey: key}
			if err := tx.
				Where("role_id = ? AND permission_key = ?", roleID, key).
				FirstOrCreate(&rp).Error; err != nil {
				return fmt.Errorf("iam: set role permission: %w", err)
			}
		}

		// Delete permissions no longer in the set.
		if len(keys) > 0 {
			if err := tx.
				Where("role_id = ? AND permission_key NOT IN ?", roleID, keys).
				Delete(&RolePermission{}).Error; err != nil {
				return fmt.Errorf("iam: prune stale role permissions: %w", err)
			}
		} else {
			if err := tx.Where("role_id = ?", roleID).Delete(&RolePermission{}).Error; err != nil {
				return fmt.Errorf("iam: clear role permissions: %w", err)
			}
		}
		return nil
	})
}

func (r *Repository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]RolePermission, error) {
	var perms []RolePermission
	if err := r.db.WithContext(ctx).
		Where("role_id = ?", roleID).
		Find(&perms).Error; err != nil {
		return nil, fmt.Errorf("iam: get role permissions: %w", err)
	}
	return perms, nil
}

// ── Member Roles ──────────────────────────────────────────────────────────────

func (r *Repository) AssignRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	mr := MemberRole{MemberID: memberID, RoleID: roleID}
	if err := r.db.WithContext(ctx).Create(&mr).Error; err != nil {
		return fmt.Errorf("iam: assign role: %w", err)
	}
	return nil
}

func (r *Repository) RevokeRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("member_id = ? AND role_id = ?", memberID, roleID).
		Delete(&MemberRole{}).Error; err != nil {
		return fmt.Errorf("iam: revoke role: %w", err)
	}
	return nil
}

func (r *Repository) GetMemberRoles(ctx context.Context, memberID uuid.UUID) ([]MemberRole, error) {
	var mrs []MemberRole
	if err := r.db.WithContext(ctx).
		Where("member_id = ?", memberID).
		Preload("Role.Permissions").
		Find(&mrs).Error; err != nil {
		return nil, fmt.Errorf("iam: get member roles: %w", err)
	}
	return mrs, nil
}

// ── Invitations ───────────────────────────────────────────────────────────────

func (r *Repository) FindInvitationByID(ctx context.Context, id uuid.UUID) (*Invitation, error) {
	var inv Invitation
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&inv).Error; err != nil {
		return nil, fmt.Errorf("iam: find invitation: %w", err)
	}
	return &inv, nil
}

func (r *Repository) FindInvitationByToken(ctx context.Context, tokenHash string) (*Invitation, error) {
	var inv Invitation
	if err := r.db.WithContext(ctx).
		Where("token_hash = ? AND status = ?", tokenHash, types.InvitationStatusPending).
		First(&inv).Error; err != nil {
		return nil, fmt.Errorf("iam: find invitation by token: %w", err)
	}
	return &inv, nil
}

// FindInvitationByTokenForUpdate is like FindInvitationByToken but uses
// SELECT ... FOR UPDATE SKIP LOCKED to prevent concurrent acceptance.
func (r *Repository) FindInvitationByTokenForUpdate(ctx context.Context, tx *gorm.DB, tokenHash string) (*Invitation, error) {
	var inv Invitation
	if err := tx.WithContext(ctx).
		Set("gorm:query_option", "FOR UPDATE SKIP LOCKED").
		Where("token_hash = ? AND status = ?", tokenHash, types.InvitationStatusPending).
		First(&inv).Error; err != nil {
		return nil, fmt.Errorf("iam: find invitation for update: %w", err)
	}
	return &inv, nil
}

func (r *Repository) FindPendingInvitation(ctx context.Context, tenantID uuid.UUID, email, phone *string) (*Invitation, error) {
	q := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, types.InvitationStatusPending)
	if email != nil {
		q = q.Where("email = ?", *email)
	} else if phone != nil {
		q = q.Where("phone = ?", *phone)
	} else {
		return nil, fmt.Errorf("iam: invitation lookup requires email or phone")
	}

	var inv Invitation
	if err := q.First(&inv).Error; err != nil {
		return nil, fmt.Errorf("iam: find pending invitation: %w", err)
	}
	return &inv, nil
}

func (r *Repository) CreateInvitation(ctx context.Context, inv *Invitation) error {
	if err := r.db.WithContext(ctx).Create(inv).Error; err != nil {
		return fmt.Errorf("iam: create invitation: %w", err)
	}
	return nil
}

func (r *Repository) UpdateInvitation(ctx context.Context, id uuid.UUID, updates map[string]any) (*Invitation, error) {
	if err := r.db.WithContext(ctx).
		Model(&Invitation{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("iam: update invitation: %w", err)
	}
	return r.FindInvitationByID(ctx, id)
}

func (r *Repository) ListInvitations(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Invitation], error) {
	return sdk.Paginate[Invitation](
		r.db.WithContext(ctx).Where("tenant_id = ?", tenantID),
		page,
	)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parsePath splits a materialized path like "/{id1}/{id2}" into a slice
// of UUIDs. Empty segments are skipped.
func parsePath(path string) []uuid.UUID {
	if path == "" || path == "/" {
		return nil
	}
	var ids []uuid.UUID
	for _, seg := range splitPath(path) {
		if id, err := uuid.Parse(seg); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// splitPath splits a slash-separated path into non-empty segments.
func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	return parts
}
