CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    password_hash TEXT,
    name JSONB NOT NULL DEFAULT '{}',
    avatar_url TEXT,
    locale TEXT NOT NULL DEFAULT 'en',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    status TEXT NOT NULL DEFAULT 'active',
    metadata JSONB NOT NULL DEFAULT '{}',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_users_provider_id ON users(provider, provider_id)
WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_email ON users(email)
WHERE email IS NOT NULL
    AND deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_phone ON users(phone)
WHERE phone IS NOT NULL
    AND deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status);
