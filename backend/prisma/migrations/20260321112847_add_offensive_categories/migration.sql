-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ModuleCategory" ADD VALUE 'WEB_OFFENSIVE';
ALTER TYPE "ModuleCategory" ADD VALUE 'API_OFFENSIVE';
ALTER TYPE "ModuleCategory" ADD VALUE 'NETWORK_OFFENSIVE';
ALTER TYPE "ModuleCategory" ADD VALUE 'SYSTEM';

-- CreateTable
CREATE TABLE "ScanProfile" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "modules" TEXT[],
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanProfile_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "ScanProfile" ADD CONSTRAINT "ScanProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
