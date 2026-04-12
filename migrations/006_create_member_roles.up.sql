CREATE TABLE member_roles (
    id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    member_id UUID        NOT NULL REFERENCES tenant_members(id) ON DELETE CASCADE,
    role_id   UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (member_id, role_id)
);

CREATE INDEX idx_member_roles_member_id ON member_roles(member_id);
CREATE INDEX idx_member_roles_role_id   ON member_roles(role_id);
