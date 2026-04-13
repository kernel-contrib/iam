package iam

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ── Token helpers ─────────────────────────────────────────────────────────────

// generateToken creates a cryptographically random 32-byte token
// and returns it as a URL-safe base64 string.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("iam: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken computes a SHA-256 hash of the raw token string.
// Only the hash is persisted — the raw token is sent to the invitee.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ── Slug validation ───────────────────────────────────────────────────────────

// slugRe enforces lowercase alphanumeric + hyphens, 3-63 characters.
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// validateSlug returns an error if the slug does not match the required format.
func validateSlug(slug string) error {
	if !slugRe.MatchString(slug) {
		return fmt.Errorf("slug must be 3-63 lowercase alphanumeric characters or hyphens, starting and ending with alphanumeric")
	}
	return nil
}

// ── Error helpers ─────────────────────────────────────────────────────────────

// isNotFoundErr checks whether the error chain contains gorm.ErrRecordNotFound.
func isNotFoundErr(err error) bool {
	return err != nil && errors.Is(err, gorm.ErrRecordNotFound)
}

// isDuplicateError detects unique-constraint violations across both
// PostgreSQL (SQLSTATE 23505) and SQLite (UNIQUE constraint failed).
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	if containsErrCode(err, "23505") {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "unique constraint")
}

func containsErrCode(err error, code string) bool {
	type pgErr interface{ SQLState() string }
	var pe pgErr
	if errors.As(err, &pe) {
		return pe.SQLState() == code
	}
	return false
}

// ── Path helpers ──────────────────────────────────────────────────────────────

// buildPath appends a new ID segment to a materialized path.
// buildPath("/aaa", "bbb") → "/aaa/bbb"
func buildPath(parentPath, id string) string {
	if parentPath == "" || parentPath == "/" {
		return "/" + id
	}
	return parentPath + "/" + id
}

// ── Context helpers ───────────────────────────────────────────────────────────
// These centralize context key extraction so the migration from
// org_id → tenant_id only requires changes in one place.

// tenantID extracts the tenant (org) UUID from the gin context.
// Currently reads "org_id" (kernel v0.1.0). Will switch to "tenant_id"
// once the kernel URL-based tenant routing is released.
func tenantID(c *gin.Context) uuid.UUID {
	return get(c, "tenant_id")
}

// userID extracts the authenticated user's UUID from the gin context.
func userID(c *gin.Context) uuid.UUID {
	return get(c, "internal_user_id")
}

func get(c *gin.Context, key string) uuid.UUID {
	_id, ok := c.Get(key)
	if !ok {
		return uuid.Nil
	}

	id, ok := _id.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}
