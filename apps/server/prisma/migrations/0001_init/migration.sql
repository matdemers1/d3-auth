-- Case-insensitive email and username (REQ-021).
CREATE EXTENSION IF NOT EXISTS citext;

-- CreateEnum
CREATE TYPE "UserKind" AS ENUM ('owner', 'admin', 'guest');

-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('invited', 'active', 'suspended');

-- CreateEnum
CREATE TYPE "ClientType" AS ENUM ('confidential_web', 'public_native');

-- CreateEnum
CREATE TYPE "WebauthnDeviceType" AS ENUM ('single_device', 'multi_device');

-- CreateEnum
CREATE TYPE "SigningKeyStatus" AS ENUM ('next', 'current', 'retiring', 'retired');

-- CreateTable
CREATE TABLE "user" (
    "id" UUID NOT NULL,
    "email" CITEXT NOT NULL,
    "email_verified" BOOLEAN NOT NULL DEFAULT false,
    "username" CITEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "kind" "UserKind" NOT NULL DEFAULT 'guest',
    "status" "UserStatus" NOT NULL DEFAULT 'invited',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_login_at" TIMESTAMPTZ,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_credential" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "argon2id_hash" TEXT NOT NULL,
    "set_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "totp_credential" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "secret_encrypted" BYTEA NOT NULL,
    "last_used_step" BIGINT,
    "label" TEXT NOT NULL,
    "confirmed_at" TIMESTAMPTZ,

    CONSTRAINT "totp_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webauthn_credential" (
    "credential_id" BYTEA NOT NULL,
    "user_id" UUID NOT NULL,
    "webauthn_user_id" BYTEA NOT NULL,
    "public_key" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "transports" TEXT[],
    "device_type" "WebauthnDeviceType" NOT NULL,
    "backed_up" BOOLEAN NOT NULL,
    "label" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMPTZ,

    CONSTRAINT "webauthn_credential_pkey" PRIMARY KEY ("credential_id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "oidc_session_uid" TEXT,
    "ip" INET,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "revoked_at" TIMESTAMPTZ,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "trusted_device" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "user_agent" TEXT,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "revoked_at" TIMESTAMPTZ,

    CONSTRAINT "trusted_device_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "invite" (
    "id" UUID NOT NULL,
    "email" CITEXT NOT NULL,
    "invited_by" UUID,
    "token_hash" TEXT NOT NULL,
    "initial_grants" JSONB NOT NULL DEFAULT '[]',
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "accepted_at" TIMESTAMPTZ,

    CONSTRAINT "invite_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app" (
    "id" UUID NOT NULL,
    "client_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "client_type" "ClientType" NOT NULL,
    "client_secret_hash" TEXT,
    "backchannel_logout_uri" TEXT,
    "post_logout_redirect_uris" TEXT[],
    "roles_claim_name" TEXT NOT NULL DEFAULT 'roles',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "app_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "redirect_uri" (
    "id" UUID NOT NULL,
    "app_id" UUID NOT NULL,
    "uri" TEXT NOT NULL,

    CONSTRAINT "redirect_uri_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "role" (
    "id" UUID NOT NULL,
    "app_id" UUID NOT NULL,
    "key" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "sort_order" INTEGER NOT NULL,
    "is_default" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "role_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "grant" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "app_id" UUID NOT NULL,
    "granted_by" UUID,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "grant_role" (
    "grant_id" UUID NOT NULL,
    "role_id" UUID NOT NULL,

    CONSTRAINT "grant_role_pkey" PRIMARY KEY ("grant_id","role_id")
);

-- CreateTable
CREATE TABLE "group" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',

    CONSTRAINT "group_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "group_member" (
    "group_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "group_member_pkey" PRIMARY KEY ("group_id","user_id")
);

-- CreateTable
CREATE TABLE "group_grant" (
    "id" UUID NOT NULL,
    "group_id" UUID NOT NULL,
    "app_id" UUID NOT NULL,

    CONSTRAINT "group_grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "group_grant_role" (
    "group_grant_id" UUID NOT NULL,
    "role_id" UUID NOT NULL,

    CONSTRAINT "group_grant_role_pkey" PRIMARY KEY ("group_grant_id","role_id")
);

-- CreateTable
CREATE TABLE "signing_key" (
    "kid" TEXT NOT NULL,
    "alg" TEXT NOT NULL,
    "private_jwk_encrypted" BYTEA NOT NULL,
    "public_jwk" JSONB NOT NULL,
    "status" "SigningKeyStatus" NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retire_after" TIMESTAMPTZ,

    CONSTRAINT "signing_key_pkey" PRIMARY KEY ("kid")
);

-- CreateTable
CREATE TABLE "audit_event" (
    "id" BIGSERIAL NOT NULL,
    "at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "event" TEXT NOT NULL,
    "actor_user_id" UUID,
    "target_type" TEXT,
    "target_id" TEXT,
    "ip" INET,
    "user_agent" TEXT,
    "detail" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "audit_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_payload" (
    "id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "grant_id" TEXT,
    "user_code" TEXT,
    "uid" TEXT,
    "expires_at" TIMESTAMPTZ,
    "consumed_at" TIMESTAMPTZ,

    CONSTRAINT "oidc_payload_pkey" PRIMARY KEY ("kind","id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE UNIQUE INDEX "user_username_key" ON "user"("username");

-- CreateIndex
CREATE INDEX "password_credential_user_id_idx" ON "password_credential"("user_id");

-- CreateIndex
CREATE INDEX "totp_credential_user_id_idx" ON "totp_credential"("user_id");

-- CreateIndex
CREATE INDEX "webauthn_credential_user_id_idx" ON "webauthn_credential"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "session_oidc_session_uid_key" ON "session"("oidc_session_uid");

-- CreateIndex
CREATE INDEX "session_user_id_idx" ON "session"("user_id");

-- CreateIndex
CREATE INDEX "session_expires_at_idx" ON "session"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "trusted_device_token_hash_key" ON "trusted_device"("token_hash");

-- CreateIndex
CREATE INDEX "trusted_device_user_id_idx" ON "trusted_device"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "invite_token_hash_key" ON "invite"("token_hash");

-- CreateIndex
CREATE INDEX "invite_email_idx" ON "invite"("email");

-- CreateIndex
CREATE UNIQUE INDEX "app_client_id_key" ON "app"("client_id");

-- CreateIndex
CREATE UNIQUE INDEX "redirect_uri_app_id_uri_key" ON "redirect_uri"("app_id", "uri");

-- CreateIndex
CREATE UNIQUE INDEX "role_app_id_key_key" ON "role"("app_id", "key");

-- CreateIndex
CREATE INDEX "grant_app_id_idx" ON "grant"("app_id");

-- CreateIndex
CREATE UNIQUE INDEX "grant_user_id_app_id_key" ON "grant"("user_id", "app_id");

-- CreateIndex
CREATE INDEX "grant_role_role_id_idx" ON "grant_role"("role_id");

-- CreateIndex
CREATE UNIQUE INDEX "group_name_key" ON "group"("name");

-- CreateIndex
CREATE INDEX "group_member_user_id_idx" ON "group_member"("user_id");

-- CreateIndex
CREATE INDEX "group_grant_app_id_idx" ON "group_grant"("app_id");

-- CreateIndex
CREATE UNIQUE INDEX "group_grant_group_id_app_id_key" ON "group_grant"("group_id", "app_id");

-- CreateIndex
CREATE INDEX "group_grant_role_role_id_idx" ON "group_grant_role"("role_id");

-- CreateIndex
CREATE INDEX "signing_key_status_idx" ON "signing_key"("status");

-- CreateIndex
CREATE INDEX "audit_event_at_idx" ON "audit_event"("at");

-- CreateIndex
CREATE INDEX "audit_event_event_at_idx" ON "audit_event"("event", "at");

-- CreateIndex
CREATE INDEX "audit_event_actor_user_id_at_idx" ON "audit_event"("actor_user_id", "at");

-- CreateIndex
CREATE INDEX "oidc_payload_grant_id_idx" ON "oidc_payload"("grant_id");

-- CreateIndex
CREATE INDEX "oidc_payload_kind_uid_idx" ON "oidc_payload"("kind", "uid");

-- CreateIndex
CREATE INDEX "oidc_payload_kind_user_code_idx" ON "oidc_payload"("kind", "user_code");

-- CreateIndex
CREATE INDEX "oidc_payload_expires_at_idx" ON "oidc_payload"("expires_at");

-- AddForeignKey
ALTER TABLE "password_credential" ADD CONSTRAINT "password_credential_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "totp_credential" ADD CONSTRAINT "totp_credential_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webauthn_credential" ADD CONSTRAINT "webauthn_credential_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "trusted_device" ADD CONSTRAINT "trusted_device_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "invite" ADD CONSTRAINT "invite_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "redirect_uri" ADD CONSTRAINT "redirect_uri_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "app"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "role" ADD CONSTRAINT "role_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "app"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grant" ADD CONSTRAINT "grant_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grant" ADD CONSTRAINT "grant_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "app"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grant" ADD CONSTRAINT "grant_granted_by_fkey" FOREIGN KEY ("granted_by") REFERENCES "user"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grant_role" ADD CONSTRAINT "grant_role_grant_id_fkey" FOREIGN KEY ("grant_id") REFERENCES "grant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "grant_role" ADD CONSTRAINT "grant_role_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_member" ADD CONSTRAINT "group_member_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_member" ADD CONSTRAINT "group_member_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_grant" ADD CONSTRAINT "group_grant_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES "group"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_grant" ADD CONSTRAINT "group_grant_app_id_fkey" FOREIGN KEY ("app_id") REFERENCES "app"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_grant_role" ADD CONSTRAINT "group_grant_role_group_grant_id_fkey" FOREIGN KEY ("group_grant_id") REFERENCES "group_grant"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "group_grant_role" ADD CONSTRAINT "group_grant_role_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "role"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Audit events are append-only (REQ-111). A trigger, not a privilege revoke,
-- because the service connects as the table owner and an owner can re-grant itself.
CREATE FUNCTION audit_event_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_event is append-only: % rejected', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_event_no_update_delete
  BEFORE UPDATE OR DELETE ON "audit_event"
  FOR EACH ROW EXECUTE FUNCTION audit_event_append_only();

CREATE TRIGGER audit_event_no_truncate
  BEFORE TRUNCATE ON "audit_event"
  FOR EACH STATEMENT EXECUTE FUNCTION audit_event_append_only();
