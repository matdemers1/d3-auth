-- Owner-only actions need proof that the person at the keyboard is still the owner (REQ-037).
-- A session records when it last re-proved that, and the guard refuses anything older.
ALTER TABLE "session" ADD COLUMN "stepped_up_at" TIMESTAMPTZ;
