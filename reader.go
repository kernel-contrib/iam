package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kernel-contrib/sdk"
)

// ── Cache TTLs ────────────────────────────────────────────────────────────────

const (
	cacheUserTTL       = 5 * time.Minute
	cacheTenantTTL     = 10 * time.Minute
	cacheMemberTTL     = 5 * time.Minute
	cachePermissionTTL = 3 * time.Minute
	cacheAuthCfgTTL    = 5 * time.Minute
)

// ── Reader interface ──────────────────────────────────────────────────────────

// IAMReader is the cross-module reader interface.
// Other modules consume this via:
//
//	reader, err := sdk.Reader[iam.IAMReader](&m.ctx, "iam")
//
// All methods are read-only and backed by Redis cache for performance.
//
// Rules:
//   - Always scope queries by tenant to prevent cross-tenant data leaks.
//   - Resolve readers lazily in handlers, NEVER in Init().
type IAMReader interface {
	// ── Users ─────────────────────────────────────────────────────────
	GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error)
	GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error)

	// ── Tenants ───────────────────────────────────────────────────────
	GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
	GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error)
	GetTenantChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error)
	GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)

	// ── Members ───────────────────────────────────────────────────────
	GetMember(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error)
	GetMembersByIDs(ctx context.Context, tenantID uuid.UUID, memberIDs []uuid.UUID) (map[uuid.UUID]TenantMember, error)
	SearchMembersByName(ctx context.Context, tenantID uuid.UUID, query string) ([]uuid.UUID, error)
	IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
	IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

	// ── Permissions ───────────────────────────────────────────────────
	ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
	HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error)

	// ── Aggregation ───────────────────────────────────────────────────
	// GetUserAccess returns all tenant memberships for a user, each
	// enriched with assigned roles and resolved permissions. Designed
	// for aggregation endpoints (e.g. home feed) to avoid N+1 roundtrips.
	GetUserAccess(ctx context.Context, userID uuid.UUID) ([]TenantAccess, error)

	// ── Auth Providers ───────────────────────────────────────────────
	// GetAllowedProviders returns the list of enabled auth provider names
	// for a tenant. An empty slice means all providers are allowed.
	// Used by the kernel's resolveUser middleware for policy enforcement.
	GetAllowedProviders(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// ── Implementation ────────────────────────────────────────────────────────────

// iamReader is the unexported implementation registered with the kernel.
// It embeds *iamClient to delegate shared read methods (GetTenant,
// ResolvePermissions, HasPermission, GetUserAccess, GetAllowedProviders)
// and only overrides methods where the reader interface differs from
// the client (e.g. GetUserByID vs GetUser, GetMember by user+tenant).
//
// The embedded iamRegistrar provides write operations (CreateOrganization,
// Register) so that a single RegisterReader call satisfies both
// IAMReader and IAMRegistrar interfaces via Go's implicit composition.
type iamReader struct {
	*iamRegistrar
	*iamClient
}

// ── Users (reader-specific signatures) ────────────────────────────────────────

// GetUserByID delegates to the client's GetUser method.
// The reader exposes GetUserByID while the client exposes GetUser.
func (r *iamReader) GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error) {
	return r.iamClient.GetUser(ctx, userID)
}

// GetUserByProviderID delegates to the client.
func (r *iamReader) GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error) {
	return r.iamClient.GetUserByProviderID(ctx, providerID, provider)
}

// ── Tenants (reader-specific signatures) ──────────────────────────────────────

func (r *iamReader) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error) {
	return r.iamClient.GetTenantAncestors(ctx, tenantID)
}

func (r *iamReader) GetTenantChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error) {
	return r.iamClient.repo.FindTenantChildren(ctx, parentID)
}

func (r *iamReader) GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	return r.iamClient.GetOrgForTenant(ctx, tenantID)
}

// ── Members (reader-specific: keyed by user+tenant, not member ID) ────────────

func (r *iamReader) GetMember(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	if r.iamClient.redis.Client() == nil {
		return r.iamClient.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	}
	key := "member:" + userID.String() + ":" + tenantID.String()
	return sdk.Cache(ctx, r.iamClient.redis, key, cacheMemberTTL, func() (*TenantMember, error) {
		return r.iamClient.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	})
}

func (r *iamReader) GetMembersByIDs(ctx context.Context, tenantID uuid.UUID, memberIDs []uuid.UUID) (map[uuid.UUID]TenantMember, error) {
	return r.iamClient.repo.FindMembersByIDs(ctx, tenantID, memberIDs)
}

func (r *iamReader) SearchMembersByName(ctx context.Context, tenantID uuid.UUID, query string) ([]uuid.UUID, error) {
	return r.iamClient.repo.SearchMembersByName(ctx, tenantID, query)
}

func (r *iamReader) IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	_, err := r.GetMember(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *iamReader) IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return r.iamClient.IsMemberAnywhere(ctx, userID, tenantID)
}
