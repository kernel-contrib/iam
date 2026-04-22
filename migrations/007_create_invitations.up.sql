CREATE TABLE invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    invited_by UUID NOT NULL REFERENCES users(id),
    email TEXT,
    phone TEXT,
    role_id UUID NOT NULL REFERENCES roles(id),
    token_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_invitation_recipient CHECK (
        email IS NOT NULL
        OR phone IS NOT NULL
    )
);
CREATE INDEX idx_invitations_token_hash ON invitations(token_hash);
CREATE INDEX idx_invitations_tenant_id ON invitations(tenant_id);
CREATE INDEX idx_invitations_status ON invitations(status);
CREATE UNIQUE INDEX idx_invitations_tenant_email ON invitations(tenant_id, email)
WHERE status = 'pending'
    AND email IS NOT NULL;
CREATE UNIQUE INDEX idx_invitations_tenant_phone ON invitations(tenant_id, phone)
WHERE status = 'pending'
    AND phone IS NOT NULL;
