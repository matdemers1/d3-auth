-- Native step-up (AUTH-T-9.5): when a D3 Constellation grant last re-proved who it is, with a
-- passkey or an authenticator code. Keyed by the provider's grant id, so each device's sign-in
-- steps up for itself, and the row goes with the account.
CREATE TABLE "native_step_up" (
    "grant_id" TEXT NOT NULL,
    "user_id" UUID NOT NULL,
    "stepped_up_at" TIMESTAMPTZ NOT NULL,
    CONSTRAINT "native_step_up_pkey" PRIMARY KEY ("grant_id")
);

CREATE INDEX "native_step_up_user_id_idx" ON "native_step_up"("user_id");

ALTER TABLE "native_step_up" ADD CONSTRAINT "native_step_up_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
