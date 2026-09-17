-- Which preset built an app, and with what answers (REQ-143), so its paste sheet can be shown
-- again from the app's page. Neither column ever holds a secret: the answers are an address and a
-- client id, and the client secret stays a hash in client_secret_hash.
ALTER TABLE "app" ADD COLUMN     "preset" TEXT,
ADD COLUMN     "preset_inputs" JSONB NOT NULL DEFAULT '{}';
