CREATE SCHEMA peregrine;
CREATE TABLE peregrine.platform (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    issuer TEXT NOT NULL UNIQUE,
    key_set_url TEXT NOT NULL,
    auth_login_url TEXT NOT NULL
);
CREATE TABLE peregrine.registration (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL,
    client_id TEXT NOT NULL,
    UNIQUE(platform_id, client_id)
);
CREATE TABLE peregrine.deployment (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    platform_deployment_id TEXT NOT NULL,
    registration_id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE(platform_deployment_id, registration_id)
);
CREATE TABLE peregrine.platform_instance (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL,
    guid VARCHAR(255) UNIQUE NOT NULL,
    contact_email TEXT,
    description TEXT,
    name TEXT,
    url TEXT,
    product_family_code TEXT,
    version TEXT
);
CREATE TABLE peregrine.launch (
    id UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
    nonce UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    registration_id UUID NOT NULL,
    deployment_id UUID,
    platform_instance_id UUID,
    used TIMESTAMPTZ
);