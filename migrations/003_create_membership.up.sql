CREATE TABLE tenant_members (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id),
    tenant_id  UUID        NOT NULL REFERENCES tenants(id),
    status     TEXT        NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_tenant_members_user_tenant ON tenant_members(user_id, tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_tenant_members_tenant_id          ON tenant_members(tenant_id);
CREATE INDEX idx_tenant_members_user_id            ON tenant_members(user_id);
