-- AUTH-T-10.5: a browser sign-in approved from the person's phone by number matching.
CREATE TABLE "signin_approval" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "interaction_uid" TEXT NOT NULL,
    "number" INTEGER NOT NULL,
    "choices" INTEGER[],
    "browser" TEXT NOT NULL,
    "ip" TEXT,
    "requested_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ NOT NULL,
    "answered_at" TIMESTAMPTZ,
    "result" TEXT,
    "answered_grant_id" TEXT,
    "consumed_at" TIMESTAMPTZ,

    CONSTRAINT "signin_approval_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "signin_approval_user_id_requested_at_idx" ON "signin_approval"("user_id", "requested_at");

ALTER TABLE "signin_approval" ADD CONSTRAINT "signin_approval_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
