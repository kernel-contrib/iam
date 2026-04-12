package iam

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel-contrib/iam/types"
	"go.edgescale.dev/kernel/sdk"
	"gorm.io/gorm"
)

// Re-export types for callers who import only this package.

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

// ── User ──────────────────────────────────────────────────────────────────────

// User represents an identity from an external IdP (Firebase, Azure AD, etc.).
// Users are global — not scoped to any single tenant.
type User struct {
	sdk.BaseModel
	Provider     string           `json:"provider"           gorm:"not null"`
	ProviderID   string           `json:"provider_id"        gorm:"not null"`
	Email        *string          `json:"email,omitempty"`
	Phone        *string          `json:"phone,omitempty"`
	Name         json.RawMessage  `json:"name" gorm:"type:jsonb;not null;default:'{}'"`
	PasswordHash *string          `json:"-" gorm:"column:password_hash"`
	AvatarURL    *string          `json:"avatar_url,omitempty"`
	Locale       string           `json:"locale"             gorm:"not null;default:en"`
	Status       types.UserStatus `json:"status"             gorm:"not null;default:active"`
	Metadata     json.RawMessage  `json:"metadata,omitempty" gorm:"type:jsonb"`
	LastLoginAt  *time.Time       `json:"last_login_at,omitempty"`
}

// ── Tenant ────────────────────────────────────────────────────────────────────

// Tenant represents a node in the multi-level hierarchy:
// platform → organization → branch.
// The materialized path column enables efficient ancestor/descendant queries.
type Tenant struct {
	sdk.BaseModel
	ParentID *uuid.UUID         `json:"parent_id,omitempty" gorm:"type:uuid"`
	Slug     string             `json:"slug"     gorm:"not null"`
	Name     string             `json:"name"     gorm:"not null"`
	Type     types.TenantType   `json:"type"     gorm:"not null"`
	Path     string             `json:"path"     gorm:"not null"`
	Depth    int                `json:"depth"    gorm:"not null;default:0"`
	Status   types.TenantStatus `json:"status"  gorm:"not null;default:active"`
	Metadata json.RawMessage    `json:"metadata,omitempty" gorm:"type:jsonb"`
	LogoURL  *string            `json:"logo_url,omitempty"`

	// Associations (not loaded by default)
	Parent   *Tenant  `json:"parent,omitempty"   gorm:"foreignKey:ParentID"`
	Children []Tenant `json:"children,omitempty" gorm:"foreignKey:ParentID"`
}

// IsOrg returns true if this tenant is an organization.
func (t *Tenant) IsOrg() bool { return t.Type == types.TenantTypeOrganization }

// IsBranch returns true if this tenant is a branch.
func (t *Tenant) IsBranch() bool { return t.Type == types.TenantTypeBranch }

// IsPlatform returns true if this tenant is the platform root.
func (t *Tenant) IsPlatform() bool { return t.Type == types.TenantTypePlatform }

// GetMetadata unmarshals the JSONB metadata into the target.
func (t *Tenant) GetMetadata(target any) error {
	if t.Metadata == nil {
		return nil
	}
	return json.Unmarshal(t.Metadata, target)
}

// SetMetadata marshals the source into JSONB metadata.
func (t *Tenant) SetMetadata(src any) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}
	t.Metadata = data
	return nil
}

// ── Tenant Member ─────────────────────────────────────────────────────────────

// TenantMember links a user to a tenant with a membership status.
type TenantMember struct {
	sdk.BaseModel
	UserID   uuid.UUID          `json:"user_id"   gorm:"type:uuid;not null"`
	TenantID uuid.UUID          `json:"tenant_id" gorm:"type:uuid;not null"`
	Status   types.MemberStatus `json:"status"    gorm:"not null;default:active"`

	// Associations
	User   *User   `json:"user,omitempty"   gorm:"foreignKey:UserID"`
	Tenant *Tenant `json:"tenant,omitempty" gorm:"foreignKey:TenantID"`
}

// ── Role ──────────────────────────────────────────────────────────────────────

// Role defines a named set of permissions within a tenant.
// System roles (is_system=true) are seeded during provisioning and cannot
// be modified or deleted by tenant admins.
type Role struct {
	sdk.BaseModel
	TenantID    uuid.UUID `json:"tenant_id"   gorm:"type:uuid;not null"`
	Name        string    `json:"name"        gorm:"not null"`
	Slug        string    `json:"slug"        gorm:"not null"`
	Description *string   `json:"description,omitempty"`
	IsSystem    bool      `json:"is_system"   gorm:"not null;default:false"`

	// Associations
	Permissions []RolePermission `json:"permissions,omitempty" gorm:"foreignKey:RoleID"`
}

// ── Role Permission ───────────────────────────────────────────────────────────

// RolePermission maps a single permission key to a role.
type RolePermission struct {
	ID            uuid.UUID `json:"id"             gorm:"type:uuid;primaryKey"`
	RoleID        uuid.UUID `json:"role_id"        gorm:"type:uuid;not null"`
	PermissionKey string    `json:"permission_key" gorm:"not null"`
	CreatedAt     time.Time `json:"created_at"     gorm:"autoCreateTime"`
}

// BeforeCreate generates a new UUID if one has not been set already.
func (rp *RolePermission) BeforeCreate(_ *gorm.DB) error {
	if rp.ID == uuid.Nil {
		rp.ID = uuid.New()
	}
	return nil
}

// ── Member Role ───────────────────────────────────────────────────────────────

// MemberRole assigns a role to a tenant member.
type MemberRole struct {
	ID        uuid.UUID `json:"id"        gorm:"type:uuid;primaryKey"`
	MemberID  uuid.UUID `json:"member_id" gorm:"type:uuid;not null"`
	RoleID    uuid.UUID `json:"role_id"   gorm:"type:uuid;not null"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`

	// Associations
	Role *Role `json:"role,omitempty" gorm:"foreignKey:RoleID"`
}

// BeforeCreate generates a new UUID if one has not been set already.
func (mr *MemberRole) BeforeCreate(_ *gorm.DB) error {
	if mr.ID == uuid.Nil {
		mr.ID = uuid.New()
	}
	return nil
}

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
