package iam

import (
	"context"
)

// ── Registrar interface ───────────────────────────────────────────────────────

// IAMRegistrar is the cross-module write interface for registration flows.
// Other modules consume this via:
//
//	registrar, err := sdk.Reader[iam.IAMRegistrar](&m.ctx, "iam")
//
// This allows modules like "onboarding" to orchestrate tenant creation
// without importing the IAM package directly.
//
// Rules:
//   - Resolve lazily in handlers, NEVER in Init().
//   - The underlying RegistrationService manages transactions, events,
//     and cache invalidation. Callers should not duplicate that logic.
type IAMRegistrar interface {
	CreateOrganization(ctx context.Context, in CreateOrgForUserInput) (*CreateOrgOutput, error)
	Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error)
}

// ── Implementation ────────────────────────────────────────────────────────────

// iamRegistrar wraps the RegistrationService for cross-module access.
// It is embedded in the iamReader struct so a single RegisterReader call
// exposes both IAMReader and IAMRegistrar.
type iamRegistrar struct {
	registration *RegistrationService
}

func (r *iamRegistrar) CreateOrganization(ctx context.Context, in CreateOrgForUserInput) (*CreateOrgOutput, error) {
	return r.registration.CreateOrganization(ctx, in)
}

func (r *iamRegistrar) Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	return r.registration.Register(ctx, in)
}
