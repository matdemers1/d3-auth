-- CreateEnum
CREATE TYPE "ThrottleScope" AS ENUM ('account', 'ip');

-- CreateTable
CREATE TABLE "throttle_counter" (
    "scope" "ThrottleScope" NOT NULL,
    "key" TEXT NOT NULL,
    "failures" INTEGER NOT NULL DEFAULT 0,
    "first_failure_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_failure_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "blocked_until" TIMESTAMPTZ,

    CONSTRAINT "throttle_counter_pkey" PRIMARY KEY ("scope","key")
);

-- CreateIndex
CREATE INDEX "throttle_counter_last_failure_at_idx" ON "throttle_counter"("last_failure_at");
