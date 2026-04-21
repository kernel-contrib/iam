package iam

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kernel-contrib/iam/types"
	"go.edgescale.dev/kernel/sdk"
	"gorm.io/gorm"
)

// InvitationService provides business logic for invitation operations.
type InvitationService struct {
	repo *Repository
	bus  sdk.EventBus
	log  *slog.Logger
}

// NewInvitationService constructs an InvitationService.
func NewInvitationService(repo *Repository, bus sdk.EventBus, log *slog.Logger) *InvitationService {
	return &InvitationService{repo: repo, bus: bus, log: log}
}

// DefaultInvitationTTL is the default time-to-live for invitation tokens.
const DefaultInvitationTTL = 7 * 24 * time.Hour // 7 days

// ── Query ─────────────────────────────────────────────────────────────────────

// GetByID returns an invitation by UUID.
func (s *InvitationService) GetByID(ctx context.Context, id uuid.UUID) (*Invitation, error) {
	inv, err := s.repo.FindInvitationByID(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("invitation", id)
	}
	return inv, err
}

// List returns a paginated list of invitations for a tenant.
func (s *InvitationService) List(ctx context.Context, tenantID uuid.UUID, page sdk.PageRequest) (*sdk.PageResult[Invitation], error) {
	return s.repo.ListInvitations(ctx, tenantID, page)
}

// ── Create ────────────────────────────────────────────────────────────────────

// CreateInvitationInput contains the fields for creating an invitation.
type CreateInvitationInput struct {
	TenantID  uuid.UUID
	InvitedBy uuid.UUID
	Email     *string
	Phone     *string
	RoleID    uuid.UUID
}

// CreateInvitationOutput returns both the invitation record and the raw token
// that must be sent to the invitee (it's not stored).
type CreateInvitationOutput struct {
	Invitation *Invitation
	RawToken   string // send this to the invitee; never stored
}

// Create generates an invitation token for a tenant.
// If a pending invitation for the same recipient already exists, it is re-used
// (the token is regenerated and expiry extended).
func (s *InvitationService) Create(ctx context.Context, in CreateInvitationInput) (*CreateInvitationOutput, error) {
	if in.Email == nil && in.Phone == nil {
		return nil, sdk.BadRequest("invitation requires either email or phone")
	}

	// Check for an existing pending invitation for this recipient.
	existing, err := s.repo.FindPendingInvitation(ctx, in.TenantID, in.Email, in.Phone)
	if err == nil {
		// Re-use: regenerate token and extend expiry.
		rawToken, err := generateToken()
		if err != nil {
			return nil, err
		}

		updated, err := s.repo.UpdateInvitation(ctx, existing.ID, map[string]any{
			"token_hash": hashToken(rawToken),
			"role_id":    in.RoleID,
			"invited_by": in.InvitedBy,
			"expires_at": time.Now().Add(DefaultInvitationTTL),
		})
		if err != nil {
			return nil, err
		}

		s.publish(ctx, "iam.invitation.created", map[string]any{
			"invitation_id": updated.ID,
			"tenant_id":     in.TenantID,
			"resent":        true,
		})

		return &CreateInvitationOutput{Invitation: updated, RawToken: rawToken}, nil
	}
	if !isNotFoundErr(err) {
		return nil, err
	}

	// Create a new invitation.
	rawToken, err := generateToken()
	if err != nil {
		return nil, err
	}

	inv := &Invitation{
		TenantID:  in.TenantID,
		InvitedBy: in.InvitedBy,
		Email:     in.Email,
		Phone:     in.Phone,
		RoleID:    in.RoleID,
		TokenHash: hashToken(rawToken),
		Status:    types.InvitationStatusPending,
		ExpiresAt: time.Now().Add(DefaultInvitationTTL),
	}

	if err := s.repo.CreateInvitation(ctx, inv); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict("a pending invitation for this recipient already exists")
		}
		return nil, fmt.Errorf("iam: create invitation: %w", err)
	}

	s.publish(ctx, "iam.invitation.created", map[string]any{
		"invitation_id": inv.ID,
		"tenant_id":     in.TenantID,
		"resent":        false,
	})

	return &CreateInvitationOutput{Invitation: inv, RawToken: rawToken}, nil
}

// ── Revoke ────────────────────────────────────────────────────────────────────

// Revoke marks a pending invitation as revoked.
func (s *InvitationService) Revoke(ctx context.Context, id uuid.UUID) error {
	inv, err := s.repo.FindInvitationByID(ctx, id)
	if isNotFoundErr(err) {
		return sdk.NotFound("invitation", id)
	}
	if err != nil {
		return err
	}
	if inv.Status != types.InvitationStatusPending {
		return sdk.BadRequest(fmt.Sprintf("cannot revoke invitation in status %q", inv.Status))
	}

	_, err = s.repo.UpdateInvitation(ctx, id, map[string]any{
		"status": types.InvitationStatusRevoked,
	})
	return err
}

// ── Accept ────────────────────────────────────────────────────────────────────

// AcceptInput contains the raw invitation token and the accepting user's ID.
type AcceptInput struct {
	RawToken string
	UserID   uuid.UUID
}

// Accept processes an invitation token:
//  1. Hash the raw token and look up the invitation with FOR UPDATE SKIP LOCKED.
//  2. Validate the invitation is still pending and not expired.
//  3. Create the membership + assign the designated role.
//  4. Mark the invitation as accepted.
//
// All steps run in a single transaction for consistency.
func (s *InvitationService) Accept(ctx context.Context, db *gorm.DB, in AcceptInput) (*TenantMember, error) {
	hash := hashToken(in.RawToken)

	var member *TenantMember

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Lock the invitation row.
		inv, err := s.repo.FindInvitationByTokenForUpdate(ctx, tx, hash)
		if isNotFoundErr(err) {
			return sdk.NotFound("invitation", "token")
		}
		if err != nil {
			return err
		}

		// 2. Validate status and expiry.
		if inv.Status != types.InvitationStatusPending {
			return sdk.BadRequest(fmt.Sprintf("invitation is %s", inv.Status))
		}
		if time.Now().After(inv.ExpiresAt) {
			// Mark as expired.
			tx.Model(&Invitation{}).Where("id = ?", inv.ID).
				Update("status", types.InvitationStatusExpired)
			return sdk.BadRequest("invitation has expired")
		}

		// 3. Create membership.
		member = &TenantMember{
			UserID:   in.UserID,
			TenantID: inv.TenantID,
			Status:   MemberStatusActive,
		}
		if err := tx.Create(member).Error; err != nil {
			if isDuplicateError(err) {
				// User is already a member — still accept the invitation.
				existing := &TenantMember{}
				if err := tx.Where("user_id = ? AND tenant_id = ?", in.UserID, inv.TenantID).
					First(existing).Error; err != nil {
					return err
				}
				member = existing
			} else {
				return fmt.Errorf("iam: create membership from invitation: %w", err)
			}
		}

		// 4. Assign the designated role.
		mr := MemberRole{MemberID: member.ID, RoleID: inv.RoleID}
		if err := tx.Where("member_id = ? AND role_id = ?", member.ID, inv.RoleID).
			FirstOrCreate(&mr).Error; err != nil {
			return fmt.Errorf("iam: assign invitation role: %w", err)
		}

		// 5. Mark invitation accepted.
		now := time.Now()
		if err := tx.Model(&Invitation{}).Where("id = ?", inv.ID).
			Updates(map[string]any{
				"status":      types.InvitationStatusAccepted,
				"accepted_at": now,
			}).Error; err != nil {
			return fmt.Errorf("iam: mark invitation accepted: %w", err)
		}

		s.publish(ctx, "iam.invitation.accepted", map[string]any{
			"invitation_id": inv.ID,
			"tenant_id":     inv.TenantID,
			"user_id":       in.UserID,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}
	return member, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *InvitationService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
