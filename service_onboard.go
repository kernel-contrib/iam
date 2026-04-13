package iam

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// ProvisionFn seeds system roles for a new tenant and returns the admin role.
// Injected into OnboardService so both onboarding and kernel-provisioning
// hooks share the same logic (defined in provision.go).
type ProvisionFn func(ctx context.Context, tenantID uuid.UUID) (*Role, error)

// OnboardService orchestrates user onboarding.
// Given an authenticated identity (from the IdP), it:
//  1. Finds or creates the User record.
//  2. If an invitation token is provided, accepts it (joins existing tenant).
//  3. Otherwise, creates a new organization for the user.
type OnboardService struct {
	users       *UserService
	tenants    *TenantService
	members    *MemberService
	roles      *RoleService
	invites    *InvitationService
	provision  ProvisionFn
	bus        sdk.EventBus
	log        *slog.Logger
	ctx        sdk.Context // module context for DB access (invitation acceptance needs tx)
}

// NewOnboardService constructs an OnboardService.
func NewOnboardService(
	users *UserService,
	tenants *TenantService,
	members *MemberService,
	roles *RoleService,
	invites *InvitationService,
	provision ProvisionFn,
	sdkCtx sdk.Context,
	log *slog.Logger,
) *OnboardService {
	return &OnboardService{
		users:     users,
		tenants:   tenants,
		members:   members,
		roles:     roles,
		invites:   invites,
		provision: provision,
		bus:       sdkCtx.Bus,
		ctx:       sdkCtx,
		log:       log,
	}
}

// OnboardInput carries information from the authenticated identity.
type OnboardInput struct {
	// Identity fields from the IdP token.
	Provider   string // e.g. "firebase"
	ProviderID string // e.g. the Firebase UID
	Email      *string
	Phone      *string

	// Optional invitation token. If set, the user joins the inviting tenant
	// instead of creating a new org.
	InvitationToken *string

	// Fields for creating a new org (used when no invitation is provided).
	TenantName string
	TenantSlug string
	PlatformID uuid.UUID // the platform tenant ID to parent new orgs under
}

// OnboardOutput returns the user and their primary tenant context.
type OnboardOutput struct {
	User   *User   `json:"user"`
	Tenant *Tenant `json:"tenant"`
	IsNew  bool    `json:"is_new"` // true if a new org was created
}

// Execute runs the onboarding flow.
func (s *OnboardService) Execute(ctx context.Context, in OnboardInput) (*OnboardOutput, error) {
	// 1. Find or create the user.
	user, isNewUser, err := s.findOrCreateUser(ctx, in)
	if err != nil {
		return nil, err
	}

	// 2. Check user status.
	if user.Status != UserStatusActive {
		return nil, sdk.Forbidden(fmt.Sprintf("user account is %s", user.Status))
	}

	// 3. If invitation token is provided, accept it.
	if in.InvitationToken != nil && *in.InvitationToken != "" {
		member, err := s.invites.Accept(ctx, s.ctx.DB, AcceptInput{
			RawToken: *in.InvitationToken,
			UserID:   user.ID,
		})
		if err != nil {
			return nil, err
		}

		tenant, err := s.tenants.GetByID(ctx, member.TenantID)
		if err != nil {
			return nil, err
		}

		out := &OnboardOutput{User: user, Tenant: tenant, IsNew: false}
		s.publish(ctx, "iam.user.onboarded", map[string]any{
			"user_id":   user.ID,
			"tenant_id": tenant.ID,
			"is_new":    false,
		})
		return out, nil
	}

	// 4. No invitation — create a new organization.
	if in.TenantSlug == "" || in.TenantName == "" {
		return nil, sdk.BadRequest("org_name and org_slug are required when onboarding without an invitation")
	}

	org, err := s.tenants.CreateOrg(ctx, CreateOrgInput{
		Slug:       in.TenantSlug,
		Name:       in.TenantName,
		PlatformID: in.PlatformID,
	})
	if err != nil {
		return nil, err
	}

	// 5. Create membership for the user.
	member, err := s.members.Add(ctx, AddMemberInput{
		UserID:   user.ID,
		TenantID: org.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("iam: onboard: create membership: %w", err)
	}

	// 6. Seed system roles for the new org and assign admin to the founding user.
	if err := s.seedAndAssignAdmin(ctx, org.ID, member.ID); err != nil {
		return nil, err
	}

	out := &OnboardOutput{User: user, Tenant: org, IsNew: isNewUser}
	s.publish(ctx, "iam.user.onboarded", map[string]any{
		"user_id":   user.ID,
		"tenant_id": org.ID,
		"is_new":    isNewUser,
	})
	return out, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

// findOrCreateUser returns the user for the given identity, creating one if needed.
func (s *OnboardService) findOrCreateUser(ctx context.Context, in OnboardInput) (*User, bool, error) {
	// Try to find existing user by provider ID.
	existing, err := s.users.GetByProviderID(ctx, in.ProviderID, in.Provider)
	if err == nil {
		return existing, false, nil
	}
	if !isNotFoundErr(err) {
		return nil, false, err
	}

	// Create new user.
	user, err := s.users.Create(ctx, CreateUserInput{
		Provider:   in.Provider,
		ProviderID: in.ProviderID,
		Email:      in.Email,
		Phone:      in.Phone,
	})
	if err != nil {
		return nil, false, err
	}

	return user, true, nil
}

// seedAndAssignAdmin delegates to the shared ProvisionFn to seed system
// roles and then assigns the admin role to the founding member.
func (s *OnboardService) seedAndAssignAdmin(ctx context.Context, tenantID, founderMemberID uuid.UUID) error {
	adminRole, err := s.provision(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("iam: onboard: seed roles: %w", err)
	}

	if err := s.roles.AssignToMember(ctx, founderMemberID, adminRole.ID); err != nil {
		return fmt.Errorf("iam: onboard: assign admin role: %w", err)
	}

	return nil
}

func (s *OnboardService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
