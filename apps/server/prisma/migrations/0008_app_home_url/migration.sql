-- Where an app lives (AUTH-T-9.3, AUTH-ADR-008): its origin is the RFC 8707 resource D3
-- Constellation asks tokens for, so registering an app makes its audience requestable without a
-- restart. Apps a preset built already know their address; the rest stay null until their
-- manifest says.
ALTER TABLE "app" ADD COLUMN "home_url" TEXT;

UPDATE "app"
SET "home_url" = rtrim("preset_inputs"->>'address', '/') || '/'
WHERE "preset" IN ('bindery', 'immich') AND coalesce("preset_inputs"->>'address', '') <> '';
