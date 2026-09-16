-- Operator settings: mail, alert recipients, lifetimes (REQ-071).
--
-- Secrets never go in `value`. They are sealed under the KEK in `secret_encrypted`, so exporting
-- the settings, or reading the table over somebody's shoulder, gives away nothing.
CREATE TABLE "setting" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL DEFAULT '{}',
    "secret_encrypted" BYTEA,
    "updated_at" TIMESTAMPTZ NOT NULL,
    "updated_by" UUID,

    CONSTRAINT "setting_pkey" PRIMARY KEY ("key")
);
