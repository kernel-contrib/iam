package iam

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// RegisterHooks subscribes to kernel lifecycle hooks.
//
// Subscriptions:
//   - after.kernel.tenant.provisioned → seed system roles + initial admin membership
//   - before.kernel.tenant.deleted    → guard: prevent platform tenant deletion
//
// Emitted hook points (fired by IAM service layer):
//   - before.iam.tenant.deactivate   → allows other modules to block deactivation
//   - after.iam.tenant.deactivate    → notifies other modules after deactivation
func (m *Module) RegisterHooks(hooks *sdk.HookRegistry) {
	// Inject the hook registry into the TenantService so it can fire
	// before/after hooks during tenant deactivation.
	m.tenants.hooks = hooks

	// React to kernel provisioning a new tenant (org).
	// This happens when `kernel tenant provision <id>` is run from the CLI
	// or when the kernel provisions a tenant programmatically.
	hooks.After("after.kernel.tenant.provisioned", m.onTenantProvisioned)

	// Guard tenant deletion at the kernel level.
	hooks.Before("before.kernel.tenant.deleted", m.guardTenantDeletion)
}

// ── Hook handlers ─────────────────────────────────────────────────────────────

// tenantProvisionedPayload is the expected shape of the kernel's provisioning event.
type tenantProvisionedPayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
	UserID   uuid.UUID `json:"user_id"` // the user who triggered provisioning (optional)
}

// onTenantProvisioned seeds system roles and creates the initial admin
// membership when the kernel provisions a new tenant.
//
// This is the hook-based equivalent of OnboardService.seedAndAssignAdmin.
// It handles the CLI provisioning path; the onboarding path calls the
// service directly.
func (m *Module) onTenantProvisioned(ctx context.Context, payload any) error {
	// The kernel passes the payload as a struct or map. Marshal to JSON
	// so we can unmarshal into our typed struct.
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("iam: marshal tenant.provisioned hook payload: %w", err)
	}

	var p tenantProvisionedPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("iam: unmarshal tenant.provisioned hook payload: %w", err)
	}

	if p.TenantID == uuid.Nil {
		return fmt.Errorf("iam: tenant.provisioned hook: missing tenant_id")
	}

	m.ctx.Logger.Info("seeding system roles for provisioned tenant",
		"tenant_id", p.TenantID,
	)

	// Seed the 3 default system roles (admin, manager, member).
	adminRole, err := m.seedSystemRoles(ctx, p.TenantID)
	if err != nil {
		return err
	}

	// If a provisioning user was specified, create their membership and
	// assign the admin role.
	if p.UserID != uuid.Nil {
		if err := m.provisionInitialMember(ctx, p.TenantID, p.UserID, adminRole.ID); err != nil {
			return err
		}
	}

	return nil
}

// guardTenantDeletion prevents deletion of platform tenants at the hook level.
// This provides a defence-in-depth guard: even if someone bypasses
// TenantService.Deactivate (e.g., via kernel CLI), the platform tenant
// cannot be deleted.
func (m *Module) guardTenantDeletion(ctx context.Context, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("iam: marshal tenant.deleted hook payload: %w", err)
	}

	var p struct {
		TenantID uuid.UUID `json:"tenant_id"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("iam: unmarshal tenant.deleted hook payload: %w", err)
	}

	tenant, err := m.repo.FindTenantByID(ctx, p.TenantID)
	if err != nil {
		// If tenant not found in IAM, don't block — it may be a non-IAM entity.
		if isNotFoundErr(err) {
			return nil
		}
		return err
	}

	if tenant.IsPlatform() {
		return sdk.Abort(sdk.Forbidden("cannot delete the platform tenant"))
	}

	return nil
}

// ── Provisioning helpers ──────────────────────────────────────────────────────

// seedSystemRoles creates the default system roles for a tenant.
// Returns the admin role for subsequent assignment.
//
// This is extracted from OnboardService so both onboarding and
// kernel-provisioning hooks can use the same logic.
func (m *Module) seedSystemRoles(ctx context.Context, tenantID uuid.UUID) (*Role, error) {
	definitions := []struct {
		Name        string
		Slug        string
		Description string
		Permissions []string
	}{
		{
			Name:        "Admin",
			Slug:        "admin",
			Description: "Full access to all resources",
			Permissions: []string{"*"},
		},
		{
			Name:        "Manager",
			Slug:        "manager",
			Description: "Manage members and view all resources",
			Permissions: []string{
				"iam.tenants.read", "iam.members.read", "iam.members.manage",
				"iam.roles.read", "iam.invitations.read", "iam.invitations.manage",
			},
		},
		{
			Name:        "Member",
			Slug:        "member",
			Description: "Basic access to tenant resources",
			Permissions: []string{
				"iam.tenants.read", "iam.members.read",
			},
		},
	}

	var adminRole *Role

	for _, def := range definitions {
		desc := def.Description
		role := &Role{
			TenantID:    tenantID,
			Name:        def.Name,
			Slug:        def.Slug,
			Description: &desc,
			IsSystem:    true,
		}
		if err := m.repo.CreateRole(ctx, role); err != nil {
			// Skip if already seeded (idempotent).
			if isDuplicateError(err) {
				existing, findErr := m.repo.FindRoleBySlugAndTenant(ctx, def.Slug, tenantID)
				if findErr != nil {
					return nil, fmt.Errorf("iam: find existing system role %s: %w", def.Slug, findErr)
				}
				if def.Slug == "admin" {
					adminRole = existing
				}
				continue
			}
			return nil, fmt.Errorf("iam: seed system role %s: %w", def.Slug, err)
		}

		if err := m.repo.SetRolePermissions(ctx, role.ID, def.Permissions); err != nil {
			return nil, fmt.Errorf("iam: seed permissions for role %s: %w", def.Slug, err)
		}

		if def.Slug == "admin" {
			adminRole = role
		}
	}

	return adminRole, nil
}

// provisionInitialMember creates a membership for the provisioning user
// and assigns them the admin role.
func (m *Module) provisionInitialMember(ctx context.Context, tenantID, userID, adminRoleID uuid.UUID) error {
	member, err := m.members.Add(ctx, AddMemberInput{
		UserID:   userID,
		TenantID: tenantID,
	})
	if err != nil {
		// If already a member, find the existing membership.
		existing, findErr := m.members.GetByUserAndTenant(ctx, userID, tenantID)
		if findErr != nil {
			return fmt.Errorf("iam: provision member: %w", err)
		}
		member = existing
	}

	if err := m.roles.AssignToMember(ctx, member.ID, adminRoleID); err != nil {
		// Ignore duplicate assignment (idempotent).
		if !isDuplicateError(err) {
			return fmt.Errorf("iam: provision admin role: %w", err)
		}
	}

	m.ctx.Logger.Info("provisioned initial admin member",
		"tenant_id", tenantID,
		"user_id", userID,
		"member_id", member.ID,
	)

	return nil
}
