-- CreateTable
CREATE TABLE IF NOT EXISTS "UserPermissions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "maxScansPerDay" INTEGER NOT NULL DEFAULT 10,
    "maxScansPerMonth" INTEGER NOT NULL DEFAULT 100,
    "maxConcurrentScans" INTEGER NOT NULL DEFAULT 2,
    "maxTargetsPerScan" INTEGER NOT NULL DEFAULT 1,
    "maxThreads" INTEGER NOT NULL DEFAULT 5,
    "maxScanDuration" INTEGER NOT NULL DEFAULT 300,
    "maxScanDepth" TEXT NOT NULL DEFAULT 'normal',
    "allowedCategories" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "blockedModules" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "canUseOffensiveModules" BOOLEAN NOT NULL DEFAULT false,
    "canGenerateReports" BOOLEAN NOT NULL DEFAULT true,
    "canExportData" BOOLEAN NOT NULL DEFAULT true,
    "canCreateProfiles" BOOLEAN NOT NULL DEFAULT true,
    "canScanInternalIPs" BOOLEAN NOT NULL DEFAULT false,
    "canUseDeepScan" BOOLEAN NOT NULL DEFAULT false,
    "canScheduleScans" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "UserPermissions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "UserPermissions_userId_key" ON "UserPermissions"("userId");

-- AddForeignKey
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'UserPermissions_userId_fkey'
  ) THEN
    ALTER TABLE "UserPermissions" ADD CONSTRAINT "UserPermissions_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

-- AlterTable: Add vulnerability extended fields
ALTER TABLE "Vulnerability"
  ADD COLUMN IF NOT EXISTS "cvssVector" TEXT,
  ADD COLUMN IF NOT EXISTS "cweId" TEXT,
  ADD COLUMN IF NOT EXISTS "evidence" TEXT,
  ADD COLUMN IF NOT EXISTS "impact" TEXT,
  ADD COLUMN IF NOT EXISTS "isResolved" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "isFalsePositive" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "notes" TEXT,
  ADD COLUMN IF NOT EXISTS "resolvedAt" TIMESTAMP(3);

-- AlterTable: Add ScanProfile unique constraint
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'ScanProfile_userId_name_key'
  ) THEN
    ALTER TABLE "ScanProfile" ADD CONSTRAINT "ScanProfile_userId_name_key"
      UNIQUE ("userId", "name");
  END IF;
END $$;
