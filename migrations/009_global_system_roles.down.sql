-- Rollback: remove global system roles and restore tenant_id NOT NULL.
-- 1. Delete global system roles (cascades to role_permissions and member_roles).
DELETE FROM roles
WHERE tenant_id IS NULL
    AND is_system = TRUE;
-- 2. Drop the new indexes.
DROP INDEX IF EXISTS idx_roles_system_slug;
DROP INDEX IF EXISTS idx_roles_tenant_slug;
-- 3. Restore tenant_id as NOT NULL.
ALTER TABLE roles
ALTER COLUMN tenant_id
SET NOT NULL;
-- 4. Recreate the original unique index.
CREATE UNIQUE INDEX idx_roles_tenant_slug ON roles(tenant_id, slug)
WHERE deleted_at IS NULL;
