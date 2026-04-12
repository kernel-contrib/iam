CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    name        TEXT        NOT NULL,
    slug        TEXT        NOT NULL,
    description TEXT,
    is_system   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_roles_tenant_slug ON roles(tenant_id, slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_tenant_id          ON roles(tenant_id);

CREATE TABLE role_permissions (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id        UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (role_id, permission_key)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
