package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/edgescaleDev/kernel/sdk"
	"github.com/google/uuid"
	"github.com/kernel-contrib/iam/types"
	"gorm.io/gorm"
)

// ProvisionFn seeds system roles for a new tenant and returns the admin role.
// Injected into RegistrationService so both onboarding and kernel-provisioning
// hooks share the same logic (defined in provision.go).
type ProvisionFn func(ctx context.Context, tenantID uuid.UUID) (*Role, error)

// RegistrationService orchestrates self-service registration flows:
//   - Register: find-or-create a user from an authenticated IdP identity.
//   - CreateOrganization: create a new org and assign the founder as admin.
//   - AcceptInvitation: accept a pending invitation and join a tenant.
type RegistrationService struct {
	users     *UserService
	tenants   *TenantService
	members   *MemberService
	roles     *RoleService
	invites   *InvitationService
	provision ProvisionFn
	db        *gorm.DB
	bus       sdk.EventBus
	redis     sdk.NamespacedRedis
	log       *slog.Logger
}

// NewRegistrationService constructs a RegistrationService.
func NewRegistrationService(
	users *UserService,
	tenants *TenantService,
	members *MemberService,
	roles *RoleService,
	invites *InvitationService,
	provision ProvisionFn,
	db *gorm.DB,
	bus sdk.EventBus,
	redis sdk.NamespacedRedis,
	log *slog.Logger,
) *RegistrationService {
	return &RegistrationService{
		users:     users,
		tenants:   tenants,
		members:   members,
		roles:     roles,
		invites:   invites,
		provision: provision,
		db:        db,
		bus:       bus,
		redis:     redis,
		log:       log,
	}
}

// ── Register ──────────────────────────────────────────────────────────────────

// RegisterInput carries the authenticated identity from the kernel's auth context.
type RegisterInput struct {
	Provider   string          // e.g. "firebase", read from auth context
	ProviderID string          // e.g. the Firebase UID, read from auth context
	Email      *string         // optional, from request body
	Phone      *string         // optional, from request body
	Name       *string         // optional, from request body
	AvatarURL  *string         // optional, from request body
	Locale     *string         // optional, from request body
	Timezone   *string         // optional, from request body
	Metadata   json.RawMessage // optional, from request body
}

// RegisterOutput returns the user and whether it was newly created.
type RegisterOutput struct {
	User  *User `json:"user"`
	IsNew bool  `json:"is_new"`
}

// Register finds or creates a user record for the authenticated identity.
// Idempotent: calling it multiple times for the same identity returns
// the existing user with IsNew=false.
func (s *RegistrationService) Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	if in.Provider == "" || in.ProviderID == "" {
		return nil, sdk.BadRequest("provider identity is required")
	}

	// Try to find existing user by provider identity.
	existing, err := s.users.GetByProviderID(ctx, in.ProviderID, in.Provider)
	if err == nil {
		return &RegisterOutput{User: existing, IsNew: false}, nil
	}
	if !isNotFoundErr(err) {
		return nil, err
	}

	// Create new user.
	user, err := s.users.Create(ctx, CreateUserInput{
		Provider:   in.Provider,
		ProviderID: in.ProviderID,
		Email:      in.Email,
		Phone:      in.Phone,
		Name:       in.Name,
		AvatarURL:  in.AvatarURL,
		Locale:     in.Locale,
		Timezone:   in.Timezone,
		Metadata:   in.Metadata,
	})
	if err != nil {
		// Handle race condition: another request created the user between
		// our lookup and insert. Fall back to a lookup.
		if se, ok := sdk.IsServiceError(err); ok && se.HTTPStatus == 409 {
			found, findErr := s.users.GetByProviderID(ctx, in.ProviderID, in.Provider)
			if findErr != nil {
				return nil, err // return the original conflict error
			}
			return &RegisterOutput{User: found, IsNew: false}, nil
		}
		return nil, err
	}

	return &RegisterOutput{User: user, IsNew: true}, nil
}

// ── Create Organization ───────────────────────────────────────────────────────

// CreateOrgForUserInput contains the fields for creating a new organization.
type CreateOrgForUserInput struct {
	UserID     uuid.UUID // the authenticated user who becomes admin
	PlatformID uuid.UUID // resolved from kernel config
	Name       string
	Slug       string
	LogoURL    *string         // optional, URL or storage UUID
	Metadata   json.RawMessage // optional, raw JSON object
}

// CreateOrgOutput returns the new tenant, membership, and admin role.
type CreateOrgOutput struct {
	Tenant     *Tenant       `json:"tenant"`
	Membership *TenantMember `json:"membership"`
	Role       *Role         `json:"role"`
}

// CreateOrganization creates a new org under the platform, assigns
// the founding user as a member with the admin role.
// All steps run in a single transaction to prevent orphaned resources.
func (s *RegistrationService) CreateOrganization(ctx context.Context, in CreateOrgForUserInput) (*CreateOrgOutput, error) {
	if in.Name == "" {
		return nil, sdk.BadRequest("organization name is required")
	}

	// Auto-generate slug from name if not provided.
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
		if in.Slug == "" {
			return nil, sdk.BadRequest("unable to generate a slug from the organization name; please provide one explicitly")
		}
	}
	if err := validateSlug(in.Slug); err != nil {
		return nil, sdk.BadRequest(err.Error())
	}

	// Fetch the platform tenant (needed for depth and path computation).
	platform, err := s.tenants.GetByID(ctx, in.PlatformID)
	if err != nil {
		return nil, fmt.Errorf("iam: resolve platform tenant: %w", err)
	}

	// Verify the user exists.
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != UserStatusActive {
		return nil, sdk.Forbidden(fmt.Sprintf("user account is %s", user.Status))
	}

	var output CreateOrgOutput

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txRepo := NewRepository(tx)

		// 1. Create the org tenant.
		org := &Tenant{
			ParentID: &in.PlatformID,
			Slug:     in.Slug,
			Name:     in.Name,
			Type:     types.TenantTypeOrganization,
			Depth:    platform.Depth + 1,
			Status:   types.TenantStatusActive,
		}
		org.ID = uuid.New()
		org.Path = buildPath(platform.Path, org.ID.String())
		if in.LogoURL != nil {
			org.LogoURL = in.LogoURL
		}
		if in.Metadata != nil {
			org.Metadata = sdk.JSONB(in.Metadata)
		}

		if org.Depth > types.MaxTenantDepth {
			return sdk.BadRequest("maximum tenant depth exceeded")
		}

		if err := txRepo.CreateTenant(ctx, org); err != nil {
			if isDuplicateError(err) {
				return sdk.Conflict(fmt.Sprintf("a tenant with slug %q already exists under this parent", in.Slug))
			}
			return fmt.Errorf("iam: create org: %w", err)
		}

		// 2. Create membership for the founding user.
		member := &TenantMember{
			UserID:   in.UserID,
			TenantID: org.ID,
			Status:   MemberStatusActive,
		}
		if err := txRepo.CreateMember(ctx, member); err != nil {
			return fmt.Errorf("iam: create founder membership: %w", err)
		}

		// 3. Seed system roles (admin, manager, member).
		adminRole, err := seedSystemRolesInTx(ctx, txRepo, org.ID)
		if err != nil {
			return err
		}

		// 4. Assign the admin role to the founding member.
		mr := MemberRole{MemberID: member.ID, RoleID: adminRole.ID}
		if err := tx.Create(&mr).Error; err != nil {
			return fmt.Errorf("iam: assign admin role: %w", err)
		}

		output = CreateOrgOutput{
			Tenant:     org,
			Membership: member,
			Role:       adminRole,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Post-commit: publish events and invalidate cache.
	s.publish(ctx, "iam.tenant.created", map[string]any{
		"tenant_id": output.Tenant.ID,
		"type":      output.Tenant.Type,
		"slug":      output.Tenant.Slug,
		"parent_id": output.Tenant.ParentID,
	})
	s.publish(ctx, "iam.member.added", map[string]any{
		"member_id": output.Membership.ID,
		"user_id":   in.UserID,
		"tenant_id": output.Tenant.ID,
	})
	s.publish(ctx, "iam.user.onboarded", map[string]any{
		"user_id":   in.UserID,
		"tenant_id": output.Tenant.ID,
		"is_new":    true,
	})
	s.invalidateMember(ctx, in.UserID, output.Tenant.ID)

	return &output, nil
}

// ── Accept Invitation ─────────────────────────────────────────────────────────

// AcceptInviteInput contains the invitation token and the authenticated user ID.
type AcceptInviteInput struct {
	UserID uuid.UUID // read from auth context
	Token  string    // raw invitation token from request body
}

// AcceptInviteOutput returns the tenant, membership, and assigned role.
type AcceptInviteOutput struct {
	Tenant     *Tenant       `json:"tenant"`
	Membership *TenantMember `json:"membership"`
	Role       *Role         `json:"role"`
}

// PreviewInvitation validates a token and returns invitation details without
// modifying state. Used by the frontend to show a confirmation screen.
func (s *RegistrationService) PreviewInvitation(ctx context.Context, in AcceptInviteInput) (*PreviewResult, error) {
	// Verify the user exists and is active.
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != UserStatusActive {
		return nil, sdk.Forbidden(fmt.Sprintf("user account is %s", user.Status))
	}

	return s.invites.Preview(ctx, PreviewInput{
		RawToken:  in.Token,
		UserEmail: user.Email,
		UserPhone: user.Phone,
	})
}

// AcceptInvitation processes an invitation token for the authenticated user.
// Delegates the transactional work to InvitationService.Accept, then handles
// post-commit concerns (events, cache invalidation, response enrichment).
func (s *RegistrationService) AcceptInvitation(ctx context.Context, in AcceptInviteInput) (*AcceptInviteOutput, error) {
	// Verify the user exists and is active.
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != UserStatusActive {
		return nil, sdk.Forbidden(fmt.Sprintf("user account is %s", user.Status))
	}

	result, err := s.invites.Accept(ctx, s.db, AcceptInput{
		RawToken:  in.Token,
		UserID:    in.UserID,
		UserEmail: user.Email,
		UserPhone: user.Phone,
	})
	if err != nil {
		return nil, err
	}

	// Post-commit: cache invalidation (Accept bypasses MemberService).
	s.invalidateMember(ctx, in.UserID, result.TenantID)

	// Publish iam.member.added (Accept does not go through MemberService).
	s.publish(ctx, "iam.member.added", map[string]any{
		"member_id": result.Member.ID,
		"user_id":   in.UserID,
		"tenant_id": result.TenantID,
	})

	// Fetch tenant and role for the response.
	tenant, err := s.tenants.GetByID(ctx, result.TenantID)
	if err != nil {
		return nil, fmt.Errorf("iam: fetch tenant after invitation accept: %w", err)
	}

	role, err := s.roles.GetByID(ctx, result.RoleID)
	if err != nil {
		return nil, fmt.Errorf("iam: fetch role after invitation accept: %w", err)
	}

	return &AcceptInviteOutput{
		Tenant:     tenant,
		Membership: result.Member,
		Role:       role,
	}, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *RegistrationService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}

func (s *RegistrationService) invalidateMember(ctx context.Context, userID, tenantID uuid.UUID) {
	if s.redis.Client() == nil {
		return
	}
	_ = sdk.Invalidate(ctx, s.redis, "member:"+userID.String()+":"+tenantID.String())
	_ = sdk.Invalidate(ctx, s.redis, "perms:"+userID.String()+":"+tenantID.String())
}

// seedSystemRolesInTx creates the default system roles within a transaction.
// Returns the admin role for subsequent assignment.
func seedSystemRolesInTx(ctx context.Context, repo *Repository, tenantID uuid.UUID) (*Role, error) {
	defs := []struct {
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

	for _, def := range defs {
		desc := def.Description
		role := &Role{
			TenantID:    tenantID,
			Name:        def.Name,
			Slug:        def.Slug,
			Description: &desc,
			IsSystem:    true,
		}
		if err := repo.CreateRole(ctx, role); err != nil {
			if isDuplicateError(err) {
				existing, findErr := repo.FindRoleBySlugAndTenant(ctx, def.Slug, tenantID)
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

		if err := repo.SetRolePermissions(ctx, role.ID, def.Permissions); err != nil {
			return nil, fmt.Errorf("iam: seed permissions for role %s: %w", def.Slug, err)
		}

		if def.Slug == "admin" {
			adminRole = role
		}
	}

	return adminRole, nil
}
