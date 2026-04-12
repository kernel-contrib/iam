CREATE TABLE departments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  name JSONB NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_department_tenant_slug ON departments(tenant_id, slug)
WHERE deleted_at IS NULL;
CREATE INDEX idx_department_tenant_id ON departments(tenant_id);
CREATE TABLE member_departments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  membership_id UUID NOT NULL REFERENCES tenant_members(id),
  department_id UUID NOT NULL REFERENCES departments(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_member_department ON member_departments(membership_id, department_id)
WHERE deleted_at IS NULL;
