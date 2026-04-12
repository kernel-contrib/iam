package iam

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// MemberService provides business logic for tenant membership operations.
type MemberService struct {
	repo *Repository
	bus  sdk.EventBus
	log  *slog.Logger
}

// NewMemberService constructs a MemberService.
func NewMemberService(repo *Repository, bus sdk.EventBus, log *slog.Logger) *MemberService {
	return &MemberService{repo: repo, bus: bus, log: log}
}

// ── Query ─────────────────────────────────────────────────────────────────────

// GetByID returns a specific membership.
func (s *MemberService) GetByID(ctx context.Context, id uuid.UUID) (*TenantMember, error) {
	m, err := s.repo.FindMember(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("member", id)
	}
	return m, err
}

// GetByUserAndTenant finds a membership for a specific user in a specific tenant.
func (s *MemberService) GetByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	return s.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
}

// List returns a paginated list of members for a tenant.
func (s *MemberService) List(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[TenantMember], error) {
	return s.repo.ListMembers(ctx, tenantID, page)
}

// IsMember checks whether a user has a direct membership in a tenant.
func (s *MemberService) IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	_, err := s.repo.FindMemberByUserAndTenant(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// IsMemberAnywhere checks whether a user has a membership in the tenant
// or any of its ancestors (i.e. they have access through the hierarchy).
func (s *MemberService) IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	_, err := s.repo.FindMemberInAncestorChain(ctx, userID, tenantID)
	if isNotFoundErr(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ── Mutations ─────────────────────────────────────────────────────────────────

// AddMemberInput contains the fields for creating a new membership.
type AddMemberInput struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
}

// Add creates a new membership and publishes iam.member.added.
func (s *MemberService) Add(ctx context.Context, in AddMemberInput) (*TenantMember, error) {
	m := &TenantMember{
		UserID:   in.UserID,
		TenantID: in.TenantID,
		Status:   MemberStatusActive,
	}

	if err := s.repo.CreateMember(ctx, m); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict("user is already a member of this tenant")
		}
		return nil, err
	}

	s.publish(ctx, "iam.member.added", map[string]any{
		"member_id": m.ID,
		"user_id":   in.UserID,
		"tenant_id": in.TenantID,
	})

	return m, nil
}

// UpdateStatus changes a member's status (e.g., active ↔ suspended).
func (s *MemberService) UpdateStatus(ctx context.Context, id uuid.UUID, status MemberStatus) (*TenantMember, error) {
	m, err := s.repo.UpdateMember(ctx, id, map[string]any{
		"status": status,
	})
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("member", id)
	}
	return m, err
}

// Remove deletes a membership and publishes iam.member.removed.
// Member roles are cascaded via foreign key ON DELETE CASCADE.
func (s *MemberService) Remove(ctx context.Context, id uuid.UUID) error {
	m, err := s.repo.FindMember(ctx, id)
	if isNotFoundErr(err) {
		return sdk.NotFound("member", id)
	}
	if err != nil {
		return err
	}

	if err := s.repo.DeleteMember(ctx, id); err != nil {
		return err
	}

	s.publish(ctx, "iam.member.removed", map[string]any{
		"member_id": id,
		"user_id":   m.UserID,
		"tenant_id": m.TenantID,
	})

	return nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *MemberService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
