package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel-contrib/iam/types"
	"go.edgescale.dev/kernel/sdk"
)

// TenantService provides business logic for tenant hierarchy operations.
type TenantService struct {
	repo  *Repository
	bus   sdk.EventBus
	hooks *sdk.HookRegistry
	log   *slog.Logger
}

// NewTenantService constructs a TenantService.
func NewTenantService(repo *Repository, bus sdk.EventBus, hooks *sdk.HookRegistry, log *slog.Logger) *TenantService {
	return &TenantService{repo: repo, bus: bus, hooks: hooks, log: log}
}

// ── Query ─────────────────────────────────────────────────────────────────────

// GetByID returns a tenant by UUID.
func (s *TenantService) GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	t, err := s.repo.FindTenantByID(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("tenant", id)
	}
	return t, err
}

// GetBySlug returns a tenant by slug.
func (s *TenantService) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	t, err := s.repo.FindTenantBySlug(ctx, slug)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("tenant", slug)
	}
	return t, err
}

// ListChildren returns the direct child tenants of a parent.
func (s *TenantService) ListChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error) {
	return s.repo.FindTenantChildren(ctx, parentID)
}

// GetAncestors returns all ancestors of a tenant (ordered root → leaf).
func (s *TenantService) GetAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error) {
	return s.repo.FindTenantAncestors(ctx, tenantID)
}

// GetOrgForTenant walks up the hierarchy to find the nearest org ancestor.
func (s *TenantService) GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	return s.repo.FindOrgForTenant(ctx, tenantID)
}

// ── Create Organization ───────────────────────────────────────────────────────

// CreateOrgInput contains the fields for creating a new organization.
type CreateOrgInput struct {
	Slug       string
	Name       string
	PlatformID uuid.UUID // the platform tenant ID to parent under
}

// CreateOrg creates a new organization tenant under the platform root.
func (s *TenantService) CreateOrg(ctx context.Context, in CreateOrgInput) (*Tenant, error) {
	if err := validateSlug(in.Slug); err != nil {
		return nil, sdk.BadRequest(err.Error())
	}

	// Verify the platform tenant exists and is actually a platform.
	platform, err := s.repo.FindTenantByID(ctx, in.PlatformID)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("platform_tenant", in.PlatformID)
	}
	if err != nil {
		return nil, err
	}
	if !platform.IsPlatform() {
		return nil, sdk.BadRequest("parent must be a platform tenant")
	}

	t := &Tenant{
		ParentID: &in.PlatformID,
		Slug:     in.Slug,
		Name:     in.Name,
		Type:     types.TenantTypeOrganization,
		Depth:    platform.Depth + 1,
		Status:   types.TenantStatusActive,
	}
	t.ID = uuid.New()
	t.Path = buildPath(platform.Path, t.ID.String())

	if err := s.validateDepth(t.Depth); err != nil {
		return nil, err
	}

	if err := s.repo.CreateTenant(ctx, t); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict(fmt.Sprintf("a tenant with slug %q already exists under this parent", in.Slug))
		}
		return nil, fmt.Errorf("iam: create org: %w", err)
	}

	s.publish(ctx, "iam.tenant.created", map[string]any{
		"tenant_id": t.ID,
		"type":      t.Type,
		"slug":      t.Slug,
		"parent_id": t.ParentID,
	})

	return t, nil
}

// ── Create Branch ─────────────────────────────────────────────────────────────

// CreateBranchInput contains the fields for creating a new branch.
type CreateBranchInput struct {
	Slug     string
	Name     string
	TenantID uuid.UUID // the organization tenant to parent under
}

// CreateBranch creates a new branch tenant under an organization.
func (s *TenantService) CreateBranch(ctx context.Context, in CreateBranchInput) (*Tenant, error) {
	if err := validateSlug(in.Slug); err != nil {
		return nil, sdk.BadRequest(err.Error())
	}

	org, err := s.repo.FindTenantByID(ctx, in.TenantID)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("organization", in.TenantID)
	}
	if err != nil {
		return nil, err
	}
	if !org.IsOrg() {
		return nil, sdk.BadRequest("parent must be an organization tenant")
	}

	t := &Tenant{
		ParentID: &in.TenantID,
		Slug:     in.Slug,
		Name:     in.Name,
		Type:     types.TenantTypeBranch,
		Depth:    org.Depth + 1,
		Status:   types.TenantStatusActive,
	}
	t.ID = uuid.New()
	t.Path = buildPath(org.Path, t.ID.String())

	if err := s.validateDepth(t.Depth); err != nil {
		return nil, err
	}

	if err := s.repo.CreateTenant(ctx, t); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict(fmt.Sprintf("a tenant with slug %q already exists under this parent", in.Slug))
		}
		return nil, fmt.Errorf("iam: create branch: %w", err)
	}

	s.publish(ctx, "iam.tenant.created", map[string]any{
		"tenant_id": t.ID,
		"type":      t.Type,
		"slug":      t.Slug,
		"parent_id": t.ParentID,
	})

	return t, nil
}

// ── Update ────────────────────────────────────────────────────────────────────

// UpdateTenantInput is a partial update for tenant fields.
type UpdateTenantInput struct {
	Name    *string
	LogoURL *string
}

// Update patches tenant fields and publishes iam.tenant.updated.
func (s *TenantService) Update(ctx context.Context, id uuid.UUID, in UpdateTenantInput) (*Tenant, error) {
	updates := make(map[string]any)
	if in.Name != nil {
		updates["name"] = *in.Name
	}
	if in.LogoURL != nil {
		updates["logo_url"] = *in.LogoURL
	}
	if len(updates) == 0 {
		return s.repo.FindTenantByID(ctx, id)
	}

	t, err := s.repo.UpdateTenant(ctx, id, updates)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("tenant", id)
	}
	if err != nil {
		return nil, err
	}

	s.publish(ctx, "iam.tenant.updated", map[string]any{"tenant_id": id})
	return t, nil
}

// ── Deactivate ────────────────────────────────────────────────────────────────

// Deactivate soft-deletes a tenant and all its children.
// Platform tenants cannot be deactivated.
// Fires before.iam.tenant.deactivate (abortable) and after.iam.tenant.deactivate hooks.
func (s *TenantService) Deactivate(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindTenantByID(ctx, id)
	if isNotFoundErr(err) {
		return sdk.NotFound("tenant", id)
	}
	if err != nil {
		return err
	}

	if t.IsPlatform() {
		return sdk.BadRequest("cannot deactivate the platform tenant")
	}

	// Let other modules block this deactivation.
	if s.hooks != nil {
		if err := s.hooks.FireBefore(ctx, "before.iam.tenant.deactivate", t); err != nil {
			if ae, ok := sdk.IsAbortError(err); ok {
				return ae.Reason
			}
			return err
		}
	}

	// Cascade deactivate children first.
	children, err := s.repo.FindTenantChildren(ctx, id)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := s.repo.SoftDeleteTenant(ctx, child.ID); err != nil {
			return fmt.Errorf("iam: cascade deactivate child %s: %w", child.ID, err)
		}
	}

	if err := s.repo.SoftDeleteTenant(ctx, id); err != nil {
		return err
	}

	s.publish(ctx, "iam.tenant.deleted", map[string]any{
		"tenant_id": id,
		"type":      t.Type,
	})

	// Notify other modules after deactivation (cannot abort).
	if s.hooks != nil {
		s.hooks.FireAfter(ctx, "after.iam.tenant.deactivate", t)
	}

	return nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *TenantService) validateDepth(depth int) error {
	if depth > types.MaxTenantDepth {
		return sdk.BadRequest(
			fmt.Sprintf("maximum tenant nesting depth is %d", types.MaxTenantDepth),
		)
	}
	return nil
}

func (s *TenantService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
