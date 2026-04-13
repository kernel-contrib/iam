package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"go.edgescale.dev/kernel/sdk"
)

// UserService provides business logic for user lifecycle operations.
type UserService struct {
	repo *Repository
	bus  sdk.EventBus
	log  *slog.Logger
}

// NewUserService constructs a UserService.
func NewUserService(repo *Repository, bus sdk.EventBus, log *slog.Logger) *UserService {
	return &UserService{repo: repo, bus: bus, log: log}
}

// ── Query ─────────────────────────────────────────────────────────────────────

// GetByID returns a user by internal UUID.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := s.repo.FindUserByID(ctx, id)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("user", id)
	}
	return u, err
}

// GetByProviderID returns a user by (provider, provider_id) pair.
func (s *UserService) GetByProviderID(ctx context.Context, providerID, provider string) (*User, error) {
	return s.repo.FindUserByProviderID(ctx, providerID, provider)
}

// ── Mutations ─────────────────────────────────────────────────────────────────

// CreateUserInput contains the fields for creating a new user.
type CreateUserInput struct {
	Provider   string
	ProviderID string
	Email      *string
	Phone      *string
}

// Create inserts a new user and publishes iam.user.created.
func (s *UserService) Create(ctx context.Context, in CreateUserInput) (*User, error) {
	u := &User{
		Provider:   in.Provider,
		ProviderID: in.ProviderID,
		Email:      in.Email,
		Phone:      in.Phone,
	}
	if err := s.repo.CreateUser(ctx, u); err != nil {
		if isDuplicateError(err) {
			return nil, sdk.Conflict("user with this provider identity already exists")
		}
		return nil, fmt.Errorf("iam: create user: %w", err)
	}

	s.publish(ctx, "iam.user.created", map[string]any{
		"user_id":     u.ID,
		"provider":    u.Provider,
		"provider_id": u.ProviderID,
	})

	return u, nil
}

// UpdateUserInput is a partial update for user profile fields.
type UpdateUserInput struct {
	Email     *string
	Phone     *string
	Name      *string
	AvatarURL *string
	Locale    *string
	Timezone  *string
}

// Update patches user fields and publishes iam.user.updated.
func (s *UserService) Update(ctx context.Context, id uuid.UUID, in UpdateUserInput) (*User, error) {
	updates := make(map[string]any)
	if in.Email != nil {
		updates["email"] = *in.Email
	}
	if in.Phone != nil {
		updates["phone"] = *in.Phone
	}
	if in.Name != nil {
		updates["name"] = *in.Name
	}
	if in.AvatarURL != nil {
		updates["avatar_url"] = *in.AvatarURL
	}
	if in.Locale != nil {
		updates["locale"] = *in.Locale
	}
	if in.Timezone != nil {
		updates["timezone"] = *in.Timezone
	}
	if len(updates) == 0 {
		return s.repo.FindUserByID(ctx, id)
	}

	u, err := s.repo.UpdateUser(ctx, id, updates)
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("user", id)
	}
	if err != nil {
		return nil, err
	}

	s.publish(ctx, "iam.user.updated", map[string]any{"user_id": id})
	return u, nil
}

// Suspend sets a user's status to suspended and publishes iam.user.suspended.
func (s *UserService) Suspend(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := s.repo.UpdateUser(ctx, id, map[string]any{
		"status": UserStatusSuspended,
	})
	if isNotFoundErr(err) {
		return nil, sdk.NotFound("user", id)
	}
	if err != nil {
		return nil, err
	}

	s.publish(ctx, "iam.user.suspended", map[string]any{"user_id": id})
	return u, nil
}

// Erase anonymises PII for GDPR compliance.
// The external_id is hashed so it can never be reversed, while email/phone/name
// are cleared. Status is set to "erased".
func (s *UserService) Erase(ctx context.Context, id uuid.UUID) error {
	u, err := s.repo.FindUserByID(ctx, id)
	if isNotFoundErr(err) {
		return sdk.NotFound("user", id)
	}
	if err != nil {
		return err
	}

	// Hash the provider ID so it becomes unrecoverable.
	hashed := sha256.Sum256([]byte(u.ProviderID))
	hashedStr := "erased:" + base64.RawURLEncoding.EncodeToString(hashed[:])

	_, err = s.repo.UpdateUser(ctx, id, map[string]any{
		"provider_id": hashedStr,
		"email":       nil,
		"phone":       nil,
		"name":        nil,
		"avatar_url":  nil,
		"metadata":    nil,
		"status":      UserStatusErased,
	})
	if err != nil {
		return err
	}

	s.publish(ctx, "iam.user.erased", map[string]any{"user_id": id})
	return nil
}

// TouchLastLogin updates the last_login_at timestamp.
func (s *UserService) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.repo.UpdateUser(ctx, id, map[string]any{
		"last_login_at": "NOW()",
	})
	return err
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *UserService) publish(ctx context.Context, subject string, payload map[string]any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, subject, payload)
}
