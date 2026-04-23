# IAM Module

Core Identity & Access Management module for the [EdgeScale Kernel](https://go.edgescale.dev/kernel) framework.

Manages the full identity lifecycle - users, multi-level tenants, memberships, role-based access control, invitations, and per-tenant authentication provider configuration:

- **Users** - global identity records linked to external IdPs (Firebase, Azure AD, API keys, etc.)
- **Multi-level tenants** - platform → organization → branch hierarchy with materialized path queries
- **Memberships** - link users to tenants with status tracking and ancestor-chain resolution
- **RBAC** - custom and system roles with fine-grained permission assignment; supports `override` and `additive` resolution modes across the tenant hierarchy
- **Invitations** - token-based invite flow with SHA-256 hashed tokens and expiry
- **Onboarding** - self-service endpoint that finds-or-creates a user, then either accepts an invitation or creates a new organization
- **Auth provider config** - per-tenant allowlisting of identity providers
- **Cross-module reader** - other modules resolve users, tenants, memberships, and permissions via `sdk.Reader[iam.IAMReader]`

## Installation

```bash
go get github.com/kernel-contrib/iam@latest
```

## Usage

### Register with the kernel

```go
package main

import (
    "go.edgescale.dev/kernel"
    iam "github.com/kernel-contrib/iam"
)

func main() {
    k := kernel.New(kernel.LoadConfig())

    k.MustRegister(iam.New())

    k.Execute()
}
```

The IAM module is `sdk.TypeCore` - it is always active and does not require per-tenant activation.

### Full example with authentication

```go
package main

import (
    "context"

    "github.com/redis/go-redis/v9"
    "go.edgescale.dev/kernel"
    "go.edgescale.dev/kernel/sdk"

    iam "github.com/kernel-contrib/iam"
    authfirebase "github.com/kernel-contrib/auth-firebase"
)

func main() {
    ctx := context.Background()

    redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

    fb, err := authfirebase.New(ctx, authfirebase.Config{
        ProjectID: "my-firebase-project",
        Redis:     redisClient,
    })
    if err != nil {
        panic(err)
    }

    chain := sdk.NewIdentityProviderChain()
    chain.AddJWTIssuer("firebase",
        "https://securetoken.google.com/my-firebase-project", fb)
    chain.SetFallback("firebase", fb)

    k := kernel.New(kernel.LoadConfig())

    k.MustRegister(iam.New())
    k.SetIdentityProvider(chain)

    k.Execute()
}
```

### Enabling platform admin support

The kernel exposes hooks that IAM subscribes to for tenant provisioning and deletion guards. To allow platform-level administration via the CLI:

```bash
# Provision a new tenant with an initial admin user
kernel tenant provision <tenant_id> --user <user_id>

# This triggers the after.kernel.tenant.provisioned hook, which:
#   1. Seeds system roles (admin, manager, member)
#   2. Creates a membership for the specified user
#   3. Assigns the admin role to that user
```

IAM automatically registers two hooks:

| Hook point | Type | Behavior |
| --- | --- | --- |
| `after.kernel.tenant.provisioned` | After | Seeds system roles and assigns admin to the provisioning user |
| `before.kernel.tenant.deleted` | Before | Prevents deletion of platform tenants (returns `sdk.Abort`) |

Platform admin check is handled by the kernel's `requirePlatformAdmin()` middleware on `/admin/v1/` routes. IAM does not currently expose admin-only routes, but any module can add them via `sdk.RouteAdmin`:

```go
func (m *Module) RouteHandlers() []sdk.RouteHandler {
    return []sdk.RouteHandler{
        {Type: sdk.RouteClient, Register: m.registerClientRoutes},
        {Type: sdk.RouteAdmin, Register: m.registerAdminRoutes},
    }
}
```

## API

### Global routes (self-service)

These routes are authenticated but not tenant-scoped: `/v1/iam/...`

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/permissions` | `iam.permissions.read` | List the permissions catalog |
| `POST` | `/onboard` | `self` | Self-service onboarding (find-or-create user, accept invite or create org) |
| `GET` | `/me` | `self` | Get the authenticated user's profile |
| `PATCH` | `/me` | `self` | Update the authenticated user's profile |
| `DELETE` | `/me` | `self` | Erase the authenticated user's PII (GDPR) |
| `GET` | `/tenants` | `self` | List tenants the authenticated user belongs to |

### Tenant-scoped routes

These routes require tenant context: `/v1/:tenant_id/iam/...`

#### Tenant

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/tenant` | `iam.tenants.read` | Get the current tenant |
| `PATCH` | `/tenant` | `iam.tenants.manage` | Update the current tenant |
| `DELETE` | `/tenant` | `iam.tenants.manage` | Deactivate the current tenant |

#### Branches (child tenants)

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/branches` | `iam.tenants.read` | List child tenants |
| `POST` | `/branches` | `iam.tenants.manage` | Create a child tenant |
| `GET` | `/branches/:id` | `iam.tenants.read` | Get a child tenant |
| `PATCH` | `/branches/:id` | `iam.tenants.manage` | Update a child tenant |
| `DELETE` | `/branches/:id` | `iam.tenants.manage` | Delete a child tenant |

#### Members

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/members` | `iam.members.read` | List tenant members |
| `POST` | `/members` | `iam.members.manage` | Add a member to the tenant |
| `GET` | `/members/:id` | `iam.members.read` | Get a member |
| `PATCH` | `/members/:id` | `iam.members.manage` | Update a member |
| `DELETE` | `/members/:id` | `iam.members.manage` | Remove a member |
| `GET` | `/members/:id/roles` | `iam.roles.read` | List roles assigned to a member |
| `POST` | `/members/:id/roles` | `iam.roles.manage` | Assign a role to a member |
| `DELETE` | `/members/:id/roles/:role_id` | `iam.roles.manage` | Revoke a role from a member |

#### Roles

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/roles` | `iam.roles.read` | List roles |
| `POST` | `/roles` | `iam.roles.manage` | Create a custom role |
| `GET` | `/roles/:id` | `iam.roles.read` | Get a role |
| `PATCH` | `/roles/:id` | `iam.roles.manage` | Update a role |
| `DELETE` | `/roles/:id` | `iam.roles.manage` | Delete a role |
| `GET` | `/roles/:id/permissions` | `iam.roles.read` | List permissions for a role |
| `PUT` | `/roles/:id/permissions` | `iam.roles.manage` | Replace all permissions for a role |

#### Invitations

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/invitations` | `iam.invitations.read` | List invitations |
| `POST` | `/invitations` | `iam.invitations.manage` | Create an invitation |
| `GET` | `/invitations/:id` | `iam.invitations.read` | Get an invitation |
| `DELETE` | `/invitations/:id` | `iam.invitations.manage` | Revoke an invitation |

#### Auth providers

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| `GET` | `/auth-providers` | `iam.tenants.manage` | List allowed auth providers |
| `PUT` | `/auth-providers` | `iam.tenants.manage` | Set allowed auth providers |

## Permissions

| Key | Description |
| --- | --- |
| `iam.tenants.read` | View tenant details |
| `iam.tenants.manage` | Create, update, and delete tenants |
| `iam.members.read` | View members |
| `iam.members.manage` | Add, update, and remove members |
| `iam.roles.read` | View roles |
| `iam.roles.manage` | Create, update, and delete roles |
| `iam.invitations.read` | View invitations |
| `iam.invitations.manage` | Create and revoke invitations |
| `iam.permissions.read` | View the permissions catalog |

## Events

| Subject | Description |
| --- | --- |
| `iam.user.created` | A new user was created |
| `iam.user.updated` | A user profile was updated |
| `iam.user.suspended` | A user was suspended |
| `iam.user.erased` | A user's PII was erased (GDPR) |
| `iam.user.onboarded` | A user completed onboarding |
| `iam.tenant.created` | A new tenant was created |
| `iam.tenant.updated` | A tenant was updated |
| `iam.tenant.deleted` | A tenant was deactivated |
| `iam.tenant.auth_config.updated` | A tenant's allowed auth providers were updated |
| `iam.member.added` | A member was added to a tenant |
| `iam.member.removed` | A member was removed from a tenant |
| `iam.role.created` | A role was created |
| `iam.role.updated` | A role was updated |
| `iam.role.deleted` | A role was deleted |
| `iam.invitation.created` | An invitation was sent |
| `iam.invitation.accepted` | An invitation was accepted |

## Configuration

Per-tenant configuration via the kernel config system:

| Key | Type | Default | Options | Description |
| --- | --- | --- | --- | --- |
| `iam.rbac_mode` | select | `override` | `override`, `additive` | How permissions are resolved across the tenant hierarchy. `override` uses the most-specific membership; `additive` unions permissions from all ancestor memberships. |

## System roles

When a new tenant is provisioned (via onboarding or CLI), the module seeds three system roles:

| Role | Slug | Permissions |
| --- | --- | --- |
| Admin | `admin` | `*` (full access) |
| Manager | `manager` | `iam.tenants.read`, `iam.members.read`, `iam.members.manage`, `iam.roles.read`, `iam.invitations.read`, `iam.invitations.manage` |
| Member | `member` | `iam.tenants.read`, `iam.members.read` |

System roles cannot be modified or deleted by tenant admins.

## Cross-module reader

Other modules can query IAM data by importing the package and using `sdk.Reader`:

```go
reader, err := sdk.Reader[iam.IAMReader](&m.ctx, "iam")
if err != nil {
    return err
}

// Users
user, err := reader.GetUserByID(ctx, userID)
user, err := reader.GetUserByProviderID(ctx, providerID, "firebase")

// Tenants
tenant, err := reader.GetTenant(ctx, tenantID)
ancestors, err := reader.GetTenantAncestors(ctx, tenantID)
children, err := reader.GetTenantChildren(ctx, parentID)
org, err := reader.GetOrgForTenant(ctx, tenantID)

// Memberships
member, err := reader.GetMember(ctx, userID, tenantID)
isMember, err := reader.IsMember(ctx, userID, tenantID)
isMemberAnywhere, err := reader.IsMemberAnywhere(ctx, userID, tenantID)

// Permissions
perms, err := reader.ResolvePermissions(ctx, userID, tenantID)
allowed, err := reader.HasPermission(ctx, userID, tenantID, "billing.invoices.read")

// Auth providers
providers, err := reader.GetAllowedProviders(ctx, tenantID)
```

All reader methods are read-only and backed by Redis cache for performance.

### IAMReader interface

External or RPC-based modules that cannot import the `iam` package directly can define the interface locally. Go's structural typing means any matching interface will satisfy `sdk.Reader`:

```go
// IAMReader is the cross-module reader interface for the IAM module.
// Copy this interface into your module to avoid a direct import dependency.
//
// Resolve at request time (never in Init):
//
//   reader, err := sdk.Reader[IAMReader](&m.ctx, "iam")
//
type IAMReader interface {
    // ── Users ─────────────────────────────────────────────────────────
    // GetUserByID returns a user by their internal UUID.
    GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error)
    // GetUserByProviderID returns a user by their external IdP identifier.
    GetUserByProviderID(ctx context.Context, providerID, provider string) (*User, error)

    // ── Tenants ───────────────────────────────────────────────────────
    // GetTenant returns a tenant by ID.
    GetTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
    // GetTenantAncestors returns all ancestors of a tenant (ordered root → parent).
    GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]Tenant, error)
    // GetTenantChildren returns direct children of a tenant.
    GetTenantChildren(ctx context.Context, parentID uuid.UUID) ([]Tenant, error)
    // GetOrgForTenant walks up the hierarchy to find the organization ancestor.
    GetOrgForTenant(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)

    // ── Members ───────────────────────────────────────────────────────
    // GetMember returns the membership for a user in a specific tenant.
    GetMember(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error)
    // IsMember checks if a user has a direct membership in a tenant.
    IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
    // IsMemberAnywhere checks if a user has membership anywhere in the tenant's ancestor chain.
    IsMemberAnywhere(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)

    // ── Permissions ───────────────────────────────────────────────────
    // ResolvePermissions returns the effective permission set for a user in a tenant,
    // respecting the configured RBAC mode (override or additive).
    ResolvePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error)
    // HasPermission checks if a user has a specific permission in a tenant.
    // Returns true if the user has the exact permission or the wildcard "*".
    HasPermission(ctx context.Context, userID, tenantID uuid.UUID, perm string) (bool, error)

    // ── Auth Providers ────────────────────────────────────────────────
    // GetAllowedProviders returns the list of enabled auth provider names for a tenant.
    // An empty slice means all providers are allowed (open by default).
    GetAllowedProviders(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}
```

> **Note:** The return types (`*User`, `*Tenant`, `*TenantMember`) must match the IAM module's exported types. If you import the `iam` package directly, use `iam.User`, `iam.Tenant`, etc. If you define local structs, they must be structurally identical for the reader assertion to succeed.

## Requirements

- Go 1.26+
- EdgeScale Kernel SDK v0.2.0+
- PostgreSQL (data storage)
- Redis (optional, for caching)
