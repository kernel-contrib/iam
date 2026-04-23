-- Per-tenant identity provider configuration.
-- Each row enables a specific auth provider for a tenant.
-- If no rows exist for a tenant, all providers are allowed (open by default).
-- Once the first row is added, it becomes a whitelist.
CREATE TABLE tenant_auth_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_tenant_auth_configs_tenant_provider_active
    ON tenant_auth_configs(tenant_id, provider_name)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_tenant_auth_configs_tenant_id ON tenant_auth_configs(tenant_id);
