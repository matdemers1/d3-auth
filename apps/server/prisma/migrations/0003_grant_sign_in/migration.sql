-- AlterTable
ALTER TABLE "grant" ADD COLUMN     "first_sign_in_at" TIMESTAMPTZ,
ADD COLUMN     "last_sign_in_at" TIMESTAMPTZ;
