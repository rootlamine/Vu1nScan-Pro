-- CreateEnum
CREATE TYPE "ModuleCategory" AS ENUM ('SECURITY', 'NETWORK', 'OSINT', 'SCRAPING');

-- AlterTable
ALTER TABLE "ScanModule" ADD COLUMN     "category" "ModuleCategory" NOT NULL DEFAULT 'SECURITY';
