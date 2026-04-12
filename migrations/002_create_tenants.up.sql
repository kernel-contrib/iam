CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID REFERENCES tenants(id),
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    depth INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    metadata JSONB,
    logo_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_tenant_depth CHECK (depth <= 2)
);
CREATE UNIQUE INDEX idx_tenants_slug ON tenants(parent_id, slug)
WHERE deleted_at IS NULL;
CREATE INDEX idx_tenants_parent_id ON tenants(parent_id);
CREATE INDEX idx_tenants_path ON tenants(path);
CREATE INDEX idx_tenants_type ON tenants(type);
CREATE INDEX idx_tenants_status ON tenants(status);