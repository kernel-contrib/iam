package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ── Cache TTLs ────────────────────────────────────────────────────────────────

const (
	cacheUserTTL       = 5 * time.Minute
	cacheTenantTTL     = 10 * time.Minute
	cacheMemberTTL     = 5 * time.Minute
	cachePermissionTTL = 3 * time.Minute
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
	IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
	IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

	// ── Permissions ───────────────────────────────────────────────────
	ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
	HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error)
}

// ── Implementation ────────────────────────────────────────────────────────────

// iamReader is the unexported implementation registered with the kernel.
// It wraps the repository for DB access, the RoleService for RBAC
// resolution, and the SDK Redis client for caching.
type iamReader struct {
	repo  *Repository
	roles *RoleService
	redis sdk.NamespacedRedis
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (r *iamReader) GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error) {
	if r.redis.Client() == nil {
		return r.repo.FindUserByID(ctx, userID)
	}
	return sdk.Cache(ctx, r.redis, "user:"+userID.String(), cacheUserTTL, func() (*User, error) {
		return r.repo.FindUserByID(ctx, userID)
	})
}

func (r *iamReader) GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error) {
	if r.redis.Client() == nil {
		return r.repo.FindUserByProviderID(ctx, providerID, provider)
	}
	return sdk.Cache(ctx, r.redis, "user:ext:"+provider+":"+providerID, cacheUserTTL, func() (*User, error) {
		return r.repo.FindUserByProviderID(ctx, providerID, provider)
	})
}

// ── Tenants ───────────────────────────────────────────────────────────────────

func (r *iamReader) GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	if r.redis.Client() == nil {
		return r.repo.FindTenantByID(ctx, tenantID)
	}
	return sdk.Cache(ctx, r.redis, "tenant:"+tenantID.String(), cacheTenantTTL, func() (*Tenant, error) {
		return r.repo.FindTenantByID(ctx, tenantID)
	})
}

func (r *iamReader) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error) {
	return r.repo.FindTenantAncestors(ctx, tenantID)
}

func (r *iamReader) GetTenantChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error) {
	return r.repo.FindTenantChildren(ctx, parentID)
}

func (r *iamReader) GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	return r.repo.FindOrgForTenant(ctx, tenantID)
}

// ── Members ───────────────────────────────────────────────────────────────────

func (r *iamReader) GetMember(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	if r.redis.Client() == nil {
		return r.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	}
	key := "member:" + userID.String() + ":" + tenantID.String()
	return sdk.Cache(ctx, r.redis, key, cacheMemberTTL, func() (*TenantMember, error) {
		return r.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	})
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
	_, err := r.repo.FindMemberInAncestorChain(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ── Permissions ───────────────────────────────────────────────────────────────

func (r *iamReader) ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	if r.redis.Client() == nil {
		return r.roles.ResolvePermissions(ctx, userID, tenantID)
	}
	key := "perms:" + userID.String() + ":" + tenantID.String()
	return sdk.Cache(ctx, r.redis, key, cachePermissionTTL, func() ([]string, error) {
		return r.roles.ResolvePermissions(ctx, userID, tenantID)
	})
}

func (r *iamReader) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error) {
	perms, err := r.ResolvePermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == "*" || p == perm {
			return true, nil
		}
	}
	return false, nil
}
