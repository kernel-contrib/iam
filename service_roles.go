package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel-contrib/iam/types"
	"go.edgescale.dev/kernel/sdk"
)

// RoleService provides business logic for RBAC operations.
type RoleService struct {
	repo             *Repository
	bus              sdk.EventBus
	log              *slog.Logger
	validPermissions func(string) bool // validates permission keys from all modules
}

// NewRoleService constructs a RoleService.
func NewRoleService(
	repo *Repository,
	bus sdk.EventBus,
	log *slog.Logger,
	validPermissions func(string) bool,
) *RoleService {
	return &RoleService{
		repo:             repo,
		bus:              bus,
		log:              log,
		validPermissions: validPermissions,
	}
}

// ── Query ─────────────────────────────────────────────────────────────────────

// GetByID returns a role by UUID.
func (s *RoleService) GetByID(ctx context.Context, id uuid.UUID) (*Role, error) {
	role, err := s.repo.FindRoleByID(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("role", id)
	}
	return role, err
}

// ListByTenant returns all roles defined for a tenant.
func (s *RoleService) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	return s.repo.FindRolesByTenant(ctx, tenantID)
}

// GetMemberRoles returns all roles assigned to a specific member.
func (s *RoleService) GetMemberRoles(ctx context.Context, memberID uuid.UUID) ([]MemberRole, error) {
	return s.repo.GetMemberRoles(ctx, memberID)
}

// ── Role CRUD ─────────────────────────────────────────────────────────────────

// CreateRoleInput contains the fields for creating a custom role.
type CreateRoleInput struct {
	TenantID    uuid.UUID
	Name        string
	Slug        string
	Description *string
}

// Create creates a custom (non-system) role.
func (s *RoleService) Create(ctx context.Context, in CreateRoleInput) (*Role, error) {
	if err := validateSlug(in.Slug); err != nil {
		return nil, sdk.BadRequest(err.Error())
	}

	role := &Role{
		TenantID:    in.TenantID,
		Name:        in.Name,
		Slug:        in.Slug,
		Description: in.Description,
		IsSystem:    false,
	}

	if err := s.repo.CreateRole(ctx, role); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict(fmt.Sprintf("a role with slug %q already exists in this tenant", in.Slug))
		}
		return nil, fmt.Errorf("iam: create role: %w", err)
	}

	s.publish(ctx, "iam.role.created", map[string]any{
		"role_id":   role.ID,
		"tenant_id": in.TenantID,
		"slug":      in.Slug,
	})

	return role, nil
}

// UpdateRoleInput is a partial update for role fields.
type UpdateRoleInput struct {
	Name        *string
	Description *string
}

// Update patches a custom role. System roles cannot be updated.
func (s *RoleService) Update(ctx context.Context, id uuid.UUID, in UpdateRoleInput) (*Role, error) {
	role, err := s.repo.FindRoleByID(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("role", id)
	}
	if err != nil {
		return nil, err
	}
	if role.IsSystem {
		return nil, sdk.BadRequest("system roles cannot be modified")
	}

	updates := make(map[string]any)
	if in.Name != nil {
		updates["name"] = *in.Name
	}
	if in.Description != nil {
		updates["description"] = *in.Description
	}
	if len(updates) == 0 {
		return role, nil
	}

	updated, err := s.repo.UpdateRole(ctx, id, updates)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, "iam.role.updated", map[string]any{"role_id": id})
	return updated, nil
}

// Delete removes a custom role. System roles cannot be deleted.
func (s *RoleService) Delete(ctx context.Context, id uuid.UUID) error {
	role, err := s.repo.FindRoleByID(ctx, id)
	if isNotFoundErr(err) {
		return sdk.NotFound("role", id)
	}
	if err != nil {
		return err
	}
	if role.IsSystem {
		return sdk.BadRequest("system roles cannot be deleted")
	}

	if err := s.repo.DeleteRole(ctx, id); err != nil {
		return err
	}

	s.publish(ctx, "iam.role.deleted", map[string]any{
		"role_id":   id,
		"tenant_id": role.TenantID,
	})
	return nil
}

// ── Permission Assignment ─────────────────────────────────────────────────────

// SetPermissions replaces all permissions for a role.
// Each key is validated against the module manifest permission registry.
func (s *RoleService) SetPermissions(ctx context.Context, roleID uuid.UUID, keys []string) error {
	role, err := s.repo.FindRoleByID(ctx, roleID)
	if isNotFoundErr(err) {
		return sdk.NotFound("role", roleID)
	}
	if err != nil {
		return err
	}
	if role.IsSystem {
		return sdk.BadRequest("system role permissions cannot be modified")
	}

	// Validate every key against the registered module permissions.
	for _, key := range keys {
		if s.validPermissions != nil && !s.validPermissions(key) {
			return sdk.BadRequest(fmt.Sprintf("unknown permission key: %s", key))
		}
	}

	return s.repo.SetRolePermissions(ctx, roleID, keys)
}

// ── Role Assignment ───────────────────────────────────────────────────────────

// AssignToMember assigns a role to a member. Both must belong to the same tenant.
func (s *RoleService) AssignToMember(ctx context.Context, memberID, roleID uuid.UUID) error {
	member, err := s.repo.FindMember(ctx, memberID)
	if isNotFoundErr(err) {
		return sdk.NotFound("member", memberID)
	}
	if err != nil {
		return err
	}

	role, err := s.repo.FindRoleByID(ctx, roleID)
	if isNotFoundErr(err) {
		return sdk.NotFound("role", roleID)
	}
	if err != nil {
		return err
	}

	// Roles must belong to the same tenant as the membership.
	if member.TenantID != role.TenantID {
		return sdk.BadRequest("role and member must belong to the same tenant")
	}

	if err := s.repo.AssignRole(ctx, memberID, roleID); err != nil {
		if isDuplicateError(err) {
			return sdk.Conflict("role is already assigned to this member")
		}
		return err
	}
	return nil
}

// RevokeFromMember removes a role from a member.
func (s *RoleService) RevokeFromMember(ctx context.Context, memberID, roleID uuid.UUID) error {
	return s.repo.RevokeRole(ctx, memberID, roleID)
}

// ── RBAC Resolution ───────────────────────────────────────────────────────────

// ResolvePermissions computes the effective permission set for a user in a
// tenant context. This is the core RBAC algorithm:
//
// 1. Collect the tenant's ancestor chain from the materialized path.
// 2. Look up the user's memberships at each level.
// 3. Depending on the tenant's RBAC mode:
//   - override: use ONLY the most-specific (deepest) membership's roles.
//   - additive: union permissions from ALL ancestor memberships.
//
// 4. Flatten role → role_permissions into a deduplicated string slice.
func (s *RoleService) ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	// 1. Get the tenant to read its path and determine RBAC mode.
	tenant, err := s.repo.FindTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	rbacMode := types.RBACModeOverride
	// Read rbac_mode from tenant metadata (set via config).
	var meta struct {
		RBACMode string `json:"rbac_mode"`
	}
	if err := tenant.GetMetadata(&meta); err == nil && meta.RBACMode != "" {
		rbacMode = types.RBACMode(meta.RBACMode)
	}

	// 2. Build the ordered chain: self first, then ancestors deepest→shallowest.
	chainIDs := []uuid.UUID{tenantID}
	ancestorIDs := parsePath(tenant.Path)
	// Reverse so deepest ancestor comes first (closest to tenant).
	for i := len(ancestorIDs) - 1; i >= 0; i-- {
		chainIDs = append(chainIDs, ancestorIDs[i])
	}

	// 3. Walk the chain collecting permissions.
	permSet := make(map[string]bool)

	for _, tid := range chainIDs {
		member, err := s.repo.FindMemberByUserAndTenant(ctx, userID, tid)
		if isNotFoundErr(err) {
			continue // no membership at this level
		}
		if err != nil {
			return nil, err
		}

		// Skip suspended members.
		if member.Status != MemberStatusActive {
			continue
		}

		memberRoles, err := s.repo.GetMemberRoles(ctx, member.ID)
		if err != nil {
			return nil, err
		}

		for _, mr := range memberRoles {
			if mr.Role == nil {
				continue
			}
			for _, rp := range mr.Role.Permissions {
				permSet[rp.PermissionKey] = true
			}
		}

		// In override mode, stop at the first (deepest) membership found.
		if rbacMode == types.RBACModeOverride {
			break
		}
		// In additive mode, continue collecting from all levels.
	}

	perms := make([]string, 0, len(permSet))
	for p := range permSet {
		perms = append(perms, p)
	}
	return perms, nil
}

// HasPermission checks if a user has a specific permission in a tenant context.
func (s *RoleService) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error) {
	perms, err := s.ResolvePermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	ps := sdk.NewPermissionSet(perms)
	return ps.Has(perm), nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *RoleService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
