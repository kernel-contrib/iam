package iam

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/kernel-contrib/sdk"
)

// RegisterHooks subscribes to kernel lifecycle hooks.
//
// Subscriptions:
//   - after.kernel.tenant.provisioned → assign admin role to the provisioning user
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
	//
	// System roles are global (tenant_id = NULL) so no per-tenant role
	// seeding is needed. We only need to assign the admin role to the
	// provisioning user.
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

// onTenantProvisioned assigns the global admin role to the provisioning user.
// System roles are global and always exist — no per-tenant seeding needed.
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

	m.ctx.Logger.Info("processing tenant provisioned hook",
		"tenant_id", p.TenantID,
	)

	// If a provisioning user was specified, create their membership and
	// assign the global admin role.
	if p.UserID != uuid.Nil {
		adminRole, err := m.repo.FindSystemRoleBySlug(ctx, "admin")
		if err != nil {
			return fmt.Errorf("iam: find global admin role: %w", err)
		}

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

// ── System role reconciliation ────────────────────────────────────────────────

// reconcileSystemRoles ensures the 3 global system roles have the correct
// permissions based on all registered module manifests. This runs once at
// boot in Init() and touches exactly 3 role rows regardless of tenant count.
//
// The reconciliation:
//   - Admin always gets "*" (wildcard).
//   - Manager and member get permissions where DefaultRoles includes their slug.
//   - Stale permissions (from removed modules) are pruned.
func (m *Module) reconcileSystemRoles(ctx context.Context) error {
	allPerms := m.ctx.AllPermissions()

	// Build the desired permission set for each system role.
	desired := map[string][]string{
		"admin":   {"*"},
		"manager": {},
		"member":  {},
	}
	for _, p := range allPerms {
		for _, roleName := range p.DefaultRoles {
			if _, ok := desired[roleName]; ok {
				desired[roleName] = append(desired[roleName], p.Key)
			}
		}
	}

	// Sync each system role's permissions to match the desired state.
	for slug, perms := range desired {
		role, err := m.repo.FindSystemRoleBySlug(ctx, slug)
		if err != nil {
			return fmt.Errorf("iam: reconcile system roles: find %s: %w", slug, err)
		}

		if err := m.repo.SetRolePermissions(ctx, role.ID, perms); err != nil {
			return fmt.Errorf("iam: reconcile system roles: sync %s permissions: %w", slug, err)
		}

		m.ctx.Logger.Info("reconciled system role permissions",
			"role", slug,
			"permission_count", len(perms),
		)
	}

	return nil
}

// ── Provisioning helpers ──────────────────────────────────────────────────────

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
