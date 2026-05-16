-- Make system roles global (tenant_id = NULL) instead of per-tenant copies.
-- This reduces role seeding from O(tenants) to O(1) and ensures all tenants
-- share the same system role definitions.
-- 1. Drop the old unique index that requires tenant_id.
DROP INDEX IF EXISTS idx_roles_tenant_slug;
-- 2. Allow tenant_id to be NULL (NULL = system/global role).
ALTER TABLE roles
ALTER COLUMN tenant_id DROP NOT NULL;
-- 3. Remove the foreign key constraint so NULL tenant_id is valid.
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_tenant_id_fkey;
-- 4. Re-add the foreign key as optional (only checked when tenant_id is not NULL).
ALTER TABLE roles
ADD CONSTRAINT roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);
-- 5. Create a partial unique index for tenant-scoped roles (custom roles).
CREATE UNIQUE INDEX idx_roles_tenant_slug ON roles(tenant_id, slug)
WHERE deleted_at IS NULL
    AND tenant_id IS NOT NULL;
-- 6. Create a partial unique index for global system roles (tenant_id IS NULL).
CREATE UNIQUE INDEX idx_roles_system_slug ON roles(slug)
WHERE deleted_at IS NULL
    AND tenant_id IS NULL;
-- 7. Delete all existing per-tenant system roles (they will be recreated as global).
--    Member role assignments pointing to these roles are also cleaned up via CASCADE
--    on the member_roles.role_id foreign key, and role_permissions via CASCADE on role_id.
DELETE FROM roles
WHERE is_system = TRUE;
-- 8. Seed the 3 global system roles.
INSERT INTO roles (
        id,
        tenant_id,
        name,
        slug,
        description,
        is_system
    )
VALUES (
        gen_random_uuid(),
        NULL,
        'Admin',
        'admin',
        'Full access to all resources',
        TRUE
    ),
    (
        gen_random_uuid(),
        NULL,
        'Manager',
        'manager',
        'Manages day-to-day operations',
        TRUE
    ),
    (
        gen_random_uuid(),
        NULL,
        'Member',
        'member',
        'Standard team member access',
        TRUE
    );
-- 9. Seed the admin wildcard permission.
INSERT INTO role_permissions (id, role_id, permission_key)
SELECT gen_random_uuid(),
    id,
    '*'
FROM roles
WHERE slug = 'admin'
    AND tenant_id IS NULL
    AND is_system = TRUE;
