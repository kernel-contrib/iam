package iam

import (
	"context"
	"fmt"

	"github.com/edgescaleDev/kernel/sdk"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IAMClient is the unified cross-module interface for the IAM module.
// Follows the AWS SDK pattern: one client per service, all operations.
//
// Consumers resolve it lazily in handlers:
//
//	client, err := sdk.Client[iam.IAMClient](&m.ctx, "iam")
type IAMClient interface {
	// Users:
	GetUser(ctx context.Context, userID uuid.UUID) (*User, error)
	GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error)
	CreateUser(ctx context.Context, in RegisterInput) (*RegisterOutput, error)
	UpdateUser(ctx context.Context, userID uuid.UUID, in UpdateUserInput) (*User, error)
	SuspendUser(ctx context.Context, userID uuid.UUID) (*User, error)
	EraseUser(ctx context.Context, userID uuid.UUID) error
	GetUserAccess(ctx context.Context, userID uuid.UUID) ([]TenantAccess, error)

	// Tenants:
	GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	CreateTenant(ctx context.Context, in CreateTenantInput) (*CreateTenantOutput, error)
	UpdateTenant(ctx context.Context, tenantID uuid.UUID, in UpdateTenantInput) (*Tenant, error)
	DeactivateTenant(ctx context.Context, tenantID uuid.UUID) error
	ListTenantChildren(ctx context.Context, parentID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Tenant], error)
	GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error)
	GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
	CreateBranch(ctx context.Context, in CreateBranchInput) (*Tenant, error)

	// Members:
	GetMember(ctx context.Context, memberID uuid.UUID) (*TenantMember, error)
	GetMemberByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error)
	GetMembersByIDs(ctx context.Context, tenantID uuid.UUID, memberIDs []uuid.UUID) (map[uuid.UUID]TenantMember, error)
	SearchMembersByName(ctx context.Context, tenantID uuid.UUID, query string) ([]uuid.UUID, error)
	ListMembers(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[TenantMember], error)
	AddMember(ctx context.Context, in AddMemberInput) (*TenantMember, error)
	UpdateMemberStatus(ctx context.Context, memberID uuid.UUID, status MemberStatus) (*TenantMember, error)
	RemoveMember(ctx context.Context, memberID uuid.UUID) error
	IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
	IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

	// Roles:
	GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error)
	ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error)
	CreateRole(ctx context.Context, in CreateRoleInput) (*Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, in UpdateRoleInput) (*Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
	SetRolePermissions(ctx context.Context, roleID uuid.UUID, keys []string) error
	GetMemberRoles(ctx context.Context, memberID uuid.UUID) ([]MemberRole, error)
	AssignRole(ctx context.Context, memberID, roleID uuid.UUID) error
	RevokeRole(ctx context.Context, memberID, roleID uuid.UUID) error
	SetMemberRole(ctx context.Context, memberID, roleID uuid.UUID) error

	// Permissions:
	ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
	HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error)

	// Invitations:
	CreateInvitation(ctx context.Context, in CreateInvitationInput) (*CreateInvitationOutput, error)
	PreviewInvitation(ctx context.Context, in AcceptInviteInput) (*PreviewResult, error)
	AcceptInvitation(ctx context.Context, in AcceptInviteInput) (*AcceptInviteOutput, error)
	RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error
	ListInvitations(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Invitation], error)

	// Auth:
	GetAllowedProviders(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// Input:

// CreateTenantInput creates an org tenant without attaching a user.
type CreateTenantInput struct {
	PlatformID uuid.UUID // auto-resolved if zero
	Name       string    // required
	Slug       string    // auto-generated from Name if empty
}

// CreateTenantOutput returns the new tenant and auto-seeded admin role.
type CreateTenantOutput struct {
	Tenant    *Tenant `json:"tenant"`
	AdminRole *Role   `json:"admin_role"`
}

// Implementation:

// iamClient is the unexported implementation of IAMClient.
type iamClient struct {
	users        *UserService
	tenants      *TenantService
	members      *MemberService
	roles        *RoleService
	invitations  *InvitationService
	registration *RegistrationService
	repo         *Repository
	redis        sdk.NamespacedRedis
	audit        sdk.AuditLogger
	db           *gorm.DB
	seedRoles    func(ctx context.Context, tenantID uuid.UUID) (*Role, error)
}

// Users:

func (c *iamClient) GetUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	if c.redis.Client() == nil {
		return c.repo.FindUserByID(ctx, userID)
	}
	return sdk.Cache(ctx, c.redis, "user:"+userID.String(), cacheUserTTL, func() (*User, error) {
		return c.repo.FindUserByID(ctx, userID)
	})
}

func (c *iamClient) GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error) {
	if c.redis.Client() == nil {
		return c.repo.FindUserByProviderID(ctx, providerID, provider)
	}
	return sdk.Cache(ctx, c.redis, "user:ext:"+provider+":"+providerID, cacheUserTTL, func() (*User, error) {
		return c.repo.FindUserByProviderID(ctx, providerID, provider)
	})
}

func (c *iamClient) CreateUser(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	out, err := c.registration.Register(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "user",
		ResourceID: out.User.ID.String(),
	})
	return out, nil
}

func (c *iamClient) UpdateUser(ctx context.Context, userID uuid.UUID, in UpdateUserInput) (*User, error) {
	user, err := c.users.Update(ctx, userID, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "user",
		ResourceID: userID.String(),
	})
	sdk.Invalidate(ctx, c.redis, "user:"+userID.String())
	return user, nil
}

func (c *iamClient) SuspendUser(ctx context.Context, userID uuid.UUID) (*User, error) {
	user, err := c.users.Suspend(ctx, userID)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "user",
		ResourceID: userID.String(),
		Changes:    map[string]sdk.AuditChange{"status": {Old: "active", New: "suspended"}},
	})
	sdk.Invalidate(ctx, c.redis, "user:"+userID.String())
	return user, nil
}

func (c *iamClient) EraseUser(ctx context.Context, userID uuid.UUID) error {
	if err := c.users.Erase(ctx, userID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "user",
		ResourceID: userID.String(),
	})
	sdk.Invalidate(ctx, c.redis, "user:"+userID.String())
	return nil
}

func (c *iamClient) GetUserAccess(ctx context.Context, userID uuid.UUID) ([]TenantAccess, error) {
	members, err := c.repo.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("iam: get user access: %w", err)
	}

	result := make([]TenantAccess, 0, len(members))
	for _, mem := range members {
		roles, err := c.roles.GetMemberRoles(ctx, mem.ID)
		if err != nil {
			return nil, fmt.Errorf("iam: get user access roles: %w", err)
		}

		perms, err := c.ResolvePermissions(ctx, userID, mem.TenantID)
		if err != nil {
			return nil, fmt.Errorf("iam: get user access permissions: %w", err)
		}

		result = append(result, TenantAccess{
			TenantMember: mem,
			Roles:        roles,
			Permissions:  perms,
		})
	}

	return result, nil
}

// Tenants

func (c *iamClient) GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	if c.redis.Client() == nil {
		return c.repo.FindTenantByID(ctx, tenantID)
	}
	return sdk.Cache(ctx, c.redis, "tenant:"+tenantID.String(), cacheTenantTTL, func() (*Tenant, error) {
		return c.repo.FindTenantByID(ctx, tenantID)
	})
}

func (c *iamClient) GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	return c.repo.FindTenantBySlug(ctx, slug)
}

func (c *iamClient) CreateTenant(ctx context.Context, in CreateTenantInput) (*CreateTenantOutput, error) {
	// Create the org tenant.
	tenant, err := c.tenants.CreateOrg(ctx, CreateOrgInput{
		PlatformID: in.PlatformID,
		Name:       in.Name,
		Slug:       in.Slug,
	})
	if err != nil {
		return nil, err
	}

	// Seed system roles.
	adminRole, err := c.seedRoles(ctx, tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("iam: seed roles for new tenant: %w", err)
	}

	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "tenant",
		ResourceID: tenant.ID.String(),
	})

	return &CreateTenantOutput{Tenant: tenant, AdminRole: adminRole}, nil
}

func (c *iamClient) UpdateTenant(ctx context.Context, tenantID uuid.UUID, in UpdateTenantInput) (*Tenant, error) {
	tenant, err := c.tenants.Update(ctx, tenantID, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "tenant",
		ResourceID: tenantID.String(),
	})
	sdk.Invalidate(ctx, c.redis, "tenant:"+tenantID.String())
	return tenant, nil
}

func (c *iamClient) DeactivateTenant(ctx context.Context, tenantID uuid.UUID) error {
	if err := c.tenants.Deactivate(ctx, tenantID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "tenant",
		ResourceID: tenantID.String(),
	})
	sdk.Invalidate(ctx, c.redis, "tenant:"+tenantID.String())
	return nil
}

func (c *iamClient) ListTenantChildren(ctx context.Context, parentID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Tenant], error) {
	return c.repo.ListTenantChildren(ctx, parentID, page)
}

func (c *iamClient) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error) {
	return c.repo.FindTenantAncestors(ctx, tenantID)
}

func (c *iamClient) GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	return c.repo.FindOrgForTenant(ctx, tenantID)
}

func (c *iamClient) CreateBranch(ctx context.Context, in CreateBranchInput) (*Tenant, error) {
	branch, err := c.tenants.CreateBranch(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "branch",
		ResourceID: branch.ID.String(),
	})
	return branch, nil
}

// Members:

func (c *iamClient) GetMember(ctx context.Context, memberID uuid.UUID) (*TenantMember, error) {
	return c.repo.FindMember(ctx, memberID)
}

func (c *iamClient) GetMemberByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	if c.redis.Client() == nil {
		return c.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	}
	key := "member:" + userID.String() + ":" + tenantID.String()
	return sdk.Cache(ctx, c.redis, key, cacheMemberTTL, func() (*TenantMember, error) {
		return c.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	})
}

func (c *iamClient) GetMembersByIDs(ctx context.Context, tenantID uuid.UUID, memberIDs []uuid.UUID) (map[uuid.UUID]TenantMember, error) {
	return c.repo.FindMembersByIDs(ctx, tenantID, memberIDs)
}

func (c *iamClient) SearchMembersByName(ctx context.Context, tenantID uuid.UUID, query string) ([]uuid.UUID, error) {
	return c.repo.SearchMembersByName(ctx, tenantID, query)
}

func (c *iamClient) ListMembers(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[TenantMember], error) {
	return c.repo.ListMembers(ctx, tenantID, page)
}

func (c *iamClient) AddMember(ctx context.Context, in AddMemberInput) (*TenantMember, error) {
	member, err := c.members.Add(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "member",
		ResourceID: member.ID.String(),
	})
	return member, nil
}

func (c *iamClient) UpdateMemberStatus(ctx context.Context, memberID uuid.UUID, status MemberStatus) (*TenantMember, error) {
	member, err := c.members.UpdateStatus(ctx, memberID, status)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "member",
		ResourceID: memberID.String(),
		Changes:    map[string]sdk.AuditChange{"status": {New: string(status)}},
	})
	return member, nil
}

func (c *iamClient) RemoveMember(ctx context.Context, memberID uuid.UUID) error {
	if err := c.members.Remove(ctx, memberID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "member",
		ResourceID: memberID.String(),
	})
	return nil
}

func (c *iamClient) IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	_, err := c.GetMemberByUserAndTenant(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *iamClient) IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	_, err := c.repo.FindMemberInAncestorChain(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Roles:

func (c *iamClient) GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	return c.repo.FindRoleByID(ctx, roleID)
}

func (c *iamClient) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	return c.repo.FindRolesByTenant(ctx, tenantID)
}

func (c *iamClient) CreateRole(ctx context.Context, in CreateRoleInput) (*Role, error) {
	role, err := c.roles.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "role",
		ResourceID: role.ID.String(),
	})
	return role, nil
}

func (c *iamClient) UpdateRole(ctx context.Context, roleID uuid.UUID, in UpdateRoleInput) (*Role, error) {
	role, err := c.roles.Update(ctx, roleID, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "role",
		ResourceID: roleID.String(),
	})
	return role, nil
}

func (c *iamClient) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	if err := c.roles.Delete(ctx, roleID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "role",
		ResourceID: roleID.String(),
	})
	return nil
}

func (c *iamClient) SetRolePermissions(ctx context.Context, roleID uuid.UUID, keys []string) error {
	if err := c.roles.SetPermissions(ctx, roleID, keys); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "role_permissions",
		ResourceID: roleID.String(),
	})
	return nil
}

func (c *iamClient) GetMemberRoles(ctx context.Context, memberID uuid.UUID) ([]MemberRole, error) {
	return c.roles.GetMemberRoles(ctx, memberID)
}

func (c *iamClient) AssignRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	if err := c.roles.AssignToMember(ctx, memberID, roleID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "member_role",
		ResourceID: memberID.String(),
		Changes:    map[string]sdk.AuditChange{"role_id": {New: roleID.String()}},
	})
	return nil
}

func (c *iamClient) RevokeRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	if err := c.roles.RevokeFromMember(ctx, memberID, roleID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditDelete,
		Resource:   "member_role",
		ResourceID: memberID.String(),
		Changes:    map[string]sdk.AuditChange{"role_id": {Old: roleID.String()}},
	})
	return nil
}

func (c *iamClient) SetMemberRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	existing, err := c.roles.GetMemberRoles(ctx, memberID)
	if err != nil {
		return fmt.Errorf("iam: get member roles: %w", err)
	}

	for _, mr := range existing {
		if err := c.roles.RevokeFromMember(ctx, memberID, mr.RoleID); err != nil {
			return fmt.Errorf("iam: revoke member role: %w", err)
		}
	}

	return c.roles.AssignToMember(ctx, memberID, roleID)
}

// Permissions:

func (c *iamClient) ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	if c.redis.Client() == nil {
		return c.roles.ResolvePermissions(ctx, userID, tenantID)
	}
	key := "perms:" + userID.String() + ":" + tenantID.String()
	return sdk.Cache(ctx, c.redis, key, cachePermissionTTL, func() ([]string, error) {
		return c.roles.ResolvePermissions(ctx, userID, tenantID)
	})
}

func (c *iamClient) HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error) {
	perms, err := c.ResolvePermissions(ctx, userID, tenantID)
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

// Invitations:

func (c *iamClient) CreateInvitation(ctx context.Context, in CreateInvitationInput) (*CreateInvitationOutput, error) {
	out, err := c.invitations.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "invitation",
		ResourceID: out.Invitation.ID.String(),
	})
	return out, nil
}

func (c *iamClient) PreviewInvitation(ctx context.Context, in AcceptInviteInput) (*PreviewResult, error) {
	return c.registration.PreviewInvitation(ctx, in)
}

func (c *iamClient) AcceptInvitation(ctx context.Context, in AcceptInviteInput) (*AcceptInviteOutput, error) {
	out, err := c.registration.AcceptInvitation(ctx, in)
	if err != nil {
		return nil, err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditCreate,
		Resource:   "invitation_accepted",
		ResourceID: out.Membership.ID.String(),
	})
	return out, nil
}

func (c *iamClient) RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error {
	if err := c.invitations.Revoke(ctx, invitationID); err != nil {
		return err
	}
	c.audit.Log(ctx, sdk.AuditEntry{
		Action:     sdk.AuditUpdate,
		Resource:   "invitation",
		ResourceID: invitationID.String(),
		Changes:    map[string]sdk.AuditChange{"status": {Old: "pending", New: "revoked"}},
	})
	return nil
}

func (c *iamClient) ListInvitations(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Invitation], error) {
	return c.repo.ListInvitations(ctx, tenantID, page)
}

// Auth:

func (c *iamClient) GetAllowedProviders(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	if c.redis.Client() == nil {
		return c.repo.ListEnabledProviders(ctx, tenantID)
	}
	key := "authcfg:" + tenantID.String()
	return sdk.Cache(ctx, c.redis, key, cacheAuthCfgTTL, func() ([]string, error) {
		return c.repo.ListEnabledProviders(ctx, tenantID)
	})
}
