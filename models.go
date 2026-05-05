package iam

import (
	"time"

	"github.com/edgescaleDev/kernel/sdk"
	"github.com/google/uuid"
	"github.com/kernel-contrib/iam/types"
	"gorm.io/gorm"
)

// Re-export enum types for callers who import only this package.
type TenantType = types.TenantType
type TenantStatus = types.TenantStatus
type UserStatus = types.UserStatus
type MemberStatus = types.MemberStatus
type InvitationStatus = types.InvitationStatus
type RBACMode = types.RBACMode

const (
	TenantTypePlatform     = types.TenantTypePlatform
	TenantTypeOrganization = types.TenantTypeOrganization
	TenantTypeBranch       = types.TenantTypeBranch

	TenantStatusActive   = types.TenantStatusActive
	TenantStatusInactive = types.TenantStatusInactive

	UserStatusActive    = types.UserStatusActive
	UserStatusSuspended = types.UserStatusSuspended
	UserStatusErased    = types.UserStatusErased

	MemberStatusActive    = types.MemberStatusActive
	MemberStatusSuspended = types.MemberStatusSuspended

	InvitationStatusPending  = types.InvitationStatusPending
	InvitationStatusAccepted = types.InvitationStatusAccepted
	InvitationStatusRevoked  = types.InvitationStatusRevoked
	InvitationStatusExpired  = types.InvitationStatusExpired

	RBACModeOverride = types.RBACModeOverride
	RBACModeAdditive = types.RBACModeAdditive
)

// Type aliases for backward compatibility.
// Existing code that references iam.User, iam.Tenant, etc. continues to work
// without any changes. Consumer modules that need these types without importing
// the root iam package can use github.com/kernel-contrib/iam/types directly.
type User = types.User
type Tenant = types.Tenant
type TenantMember = types.TenantMember
type Role = types.Role
type RolePermission = types.RolePermission
type MemberRole = types.MemberRole

// ── Invitation ────────────────────────────────────────────────────────────────

// Invitation represents a pending invitation to join a tenant.
// The raw token is sent to the invitee; only the SHA-256 hash is stored.
type Invitation struct {
	ID         uuid.UUID              `json:"id"          gorm:"type:uuid;primaryKey"`
	TenantID   uuid.UUID              `json:"tenant_id"   gorm:"type:uuid;not null"`
	InvitedBy  uuid.UUID              `json:"invited_by"  gorm:"type:uuid;not null"`
	Email      *string                `json:"email,omitempty"`
	Phone      *string                `json:"phone,omitempty"`
	RoleID     uuid.UUID              `json:"role_id"     gorm:"type:uuid;not null"`
	TokenHash  string                 `json:"-"           gorm:"not null"`
	Status     types.InvitationStatus `json:"status"      gorm:"not null;default:pending"`
	ExpiresAt  time.Time              `json:"expires_at"  gorm:"not null"`
	AcceptedAt *time.Time             `json:"accepted_at,omitempty"`
	CreatedAt  time.Time              `json:"created_at"  gorm:"autoCreateTime"`
	UpdatedAt  time.Time              `json:"updated_at"  gorm:"autoUpdateTime"`

	// Associations
	Tenant *Tenant `json:"tenant,omitempty" gorm:"foreignKey:TenantID"`
	Role   *Role   `json:"role,omitempty"   gorm:"foreignKey:RoleID"`
}

// BeforeCreate generates a new UUID if one has not been set already.
func (inv *Invitation) BeforeCreate(_ *gorm.DB) error {
	if inv.ID == uuid.Nil {
		inv.ID = uuid.New()
	}
	return nil
}

// ── Tenant Auth Config ────────────────────────────────────────────────────────

// TenantAuthConfig maps a tenant to an allowed identity provider.
// If no rows exist for a tenant, all providers are permitted (open by default).
// Once the first row is added, it becomes an allowlist — only listed providers
// are accepted for that tenant.
type TenantAuthConfig struct {
	sdk.BaseModel
	TenantID     uuid.UUID `json:"tenant_id"     gorm:"type:uuid;not null"`
	ProviderName string    `json:"provider_name" gorm:"not null"`
	IsEnabled    bool      `json:"is_enabled"    gorm:"not null;default:true"`
	Config       sdk.JSONB `json:"config,omitempty" gorm:"type:jsonb"`
}
