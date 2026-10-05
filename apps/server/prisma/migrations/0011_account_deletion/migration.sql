-- AUTH-T-10.3: an account asked to be deleted waits out a grace period, then is purged.
ALTER TABLE "user" ADD COLUMN "delete_after" TIMESTAMPTZ;
