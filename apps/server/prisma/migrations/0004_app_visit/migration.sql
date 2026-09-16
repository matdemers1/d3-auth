-- "Have they been here before?" moves off the grant and onto its own table.
--
-- Access can come from a group (P4), which has no grant row of its own, so a fact recorded on the
-- grant would be missing for exactly the people a group was meant to serve. It is also not a
-- property of the permission: it is a property of the person and the app.

CREATE TABLE "app_visit" (
    "user_id" UUID NOT NULL,
    "app_id" UUID NOT NULL,
    "first_sign_in_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_sign_in_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "app_visit_pkey" PRIMARY KEY ("user_id","app_id")
);

CREATE INDEX "app_visit_app_id_idx" ON "app_visit"("app_id");

ALTER TABLE "app_visit" ADD CONSTRAINT "app_visit_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "app_visit" ADD CONSTRAINT "app_visit_app_id_fkey"
    FOREIGN KEY ("app_id") REFERENCES "app"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Carry across what the grants already know, so nobody is shown an interstitial they have
-- already dismissed.
INSERT INTO "app_visit" ("user_id","app_id","first_sign_in_at","last_sign_in_at")
SELECT "user_id", "app_id", "first_sign_in_at", COALESCE("last_sign_in_at", "first_sign_in_at")
FROM "grant"
WHERE "first_sign_in_at" IS NOT NULL;

ALTER TABLE "grant" DROP COLUMN "first_sign_in_at";
ALTER TABLE "grant" DROP COLUMN "last_sign_in_at";
