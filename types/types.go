// Package types defines the shared domain types for the IAM module.
// It lives in its own sub-package so that reader consumers and other
// modules can import types without creating a cycle back to the parent package.
package types

// TenantType classifies tenants in the hierarchy.
type TenantType string

const (
	TenantTypePlatform     TenantType = "platform"
	TenantTypeOrganization TenantType = "organization"
	TenantTypeBranch       TenantType = "branch"
)

// TenantStatus represents the lifecycle state of a tenant.
type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
)

// UserStatus represents the lifecycle state of a user.
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusErased    UserStatus = "erased"
)

// MemberStatus represents the state of a tenant membership.
type MemberStatus string

const (
	MemberStatusActive    MemberStatus = "active"
	MemberStatusSuspended MemberStatus = "suspended"
)

// InvitationStatus represents the lifecycle state of an invitation.
type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "pending"
	InvitationStatusAccepted InvitationStatus = "accepted"
	InvitationStatusRevoked  InvitationStatus = "revoked"
	InvitationStatusExpired  InvitationStatus = "expired"
)

// RBACMode controls how permissions are resolved across the tenant hierarchy.
type RBACMode string

const (
	// RBACModeOverride means the most-specific (deepest) tenant's roles win.
	RBACModeOverride RBACMode = "override"
	// RBACModeAdditive means permissions are unioned across all ancestor memberships.
	RBACModeAdditive RBACMode = "additive"
)

// MaxTenantDepth is the maximum allowed nesting depth for the tenant hierarchy.
const MaxTenantDepth = 2
