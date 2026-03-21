-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- CreateEnum
CREATE TYPE "ReportFormat" AS ENUM ('PDF', 'JSON');

-- CreateEnum
CREATE TYPE "ModuleStatus" AS ENUM ('PENDING', 'RUNNING', 'DONE', 'ERROR');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "targetUrl" TEXT NOT NULL,
    "description" TEXT,
    "status" "ScanStatus" NOT NULL DEFAULT 'PENDING',
    "depth" TEXT NOT NULL DEFAULT 'normal',
    "threads" INTEGER NOT NULL DEFAULT 5,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "cvssScore" DOUBLE PRECISION,
    "cveId" TEXT,
    "endpoint" TEXT,
    "parameter" TEXT,
    "description" TEXT NOT NULL,
    "payload" TEXT,
    "recommendation" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanModule" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "defaultEnabled" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "ScanModule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanModuleResult" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "moduleId" TEXT NOT NULL,
    "status" "ModuleStatus" NOT NULL DEFAULT 'PENDING',
    "executionTime" INTEGER,
    "rawOutput" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanModuleResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "format" "ReportFormat" NOT NULL DEFAULT 'PDF',
    "filePath" TEXT NOT NULL,
    "fileSize" INTEGER,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "ScanModule_slug_key" ON "ScanModule"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "ScanModuleResult_scanId_moduleId_key" ON "ScanModuleResult"("scanId", "moduleId");

-- CreateIndex
CREATE UNIQUE INDEX "Report_scanId_key" ON "Report"("scanId");

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Vulnerability" ADD CONSTRAINT "Vulnerability_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanModuleResult" ADD CONSTRAINT "ScanModuleResult_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanModuleResult" ADD CONSTRAINT "ScanModuleResult_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "ScanModule"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
