-- Push registrations for D3 Constellation (AUTH-T-10.4): a device's relay and public key, owned by
-- the D3 Constellation grant that registered it.
CREATE TABLE "relay_registration" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "grant_id" TEXT NOT NULL,
    "device_public_key" BYTEA NOT NULL,
    "relay_url" TEXT NOT NULL,
    "registration" TEXT NOT NULL,
    "send_key_sealed" BYTEA NOT NULL,
    "categories" TEXT[],
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "relay_registration_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "relay_registration_grant_id_key" ON "relay_registration"("grant_id");
CREATE INDEX "relay_registration_user_id_idx" ON "relay_registration"("user_id");
CREATE UNIQUE INDEX "relay_registration_relay_url_registration_key" ON "relay_registration"("relay_url", "registration");

ALTER TABLE "relay_registration" ADD CONSTRAINT "relay_registration_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
