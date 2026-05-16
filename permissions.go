package iam

import "github.com/edgescaleDev/kernel/sdk"

// ── Simplified permission keys (preferred for new code) ───────────────────────
//
// Each module exposes exactly two permissions: read and write.
// "Write implies read" is handled by the PermReader grouping below,
// not by modifying the kernel's PermissionSet.Has().

const (
	PermRead  = "iam.read"
	PermWrite = "iam.write"
)

// PermReader matches callers who can view IAM resources.
// A user with PermWrite also passes this check because writers can read.
var PermReader = sdk.RequireAny(PermRead, PermWrite,
	PermTenantsManage, PermTenantsRead,
	PermMembersManage, PermMembersRead,
	PermRolesManage, PermRolesRead,
	PermInvitationsManage, PermInvitationsRead,
	PermPermissionsRead,
)

// PermWriter matches callers who can mutate IAM resources.
var PermWriter = sdk.RequireAny(PermWrite,
	PermTenantsManage,
	PermMembersManage,
	PermRolesManage,
	PermInvitationsManage,
	PermPermissionsRead,
)

// ── Legacy permission keys (kept for 3-5 releases, then removed) ──────────────
//
// Existing roles may reference these fine-grained keys. They remain
// in the Manifest so the kernel considers them valid. New code should
// use PermRead / PermWrite instead.

const (
	PermTenantsRead       = "iam.tenants.read"
	PermTenantsManage     = "iam.tenants.manage"
	PermMembersRead       = "iam.members.read"
	PermMembersManage     = "iam.members.manage"
	PermRolesRead         = "iam.roles.read"
	PermRolesManage       = "iam.roles.manage"
	PermInvitationsRead   = "iam.invitations.read"
	PermInvitationsManage = "iam.invitations.manage"
	PermPermissionsRead   = "iam.permissions.read"
)
