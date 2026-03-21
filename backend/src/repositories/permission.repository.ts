import { UserPermissions } from '@prisma/client';
import { prisma } from '@/utils/prisma';

export class PermissionRepository {
  async findByUserId(userId: string): Promise<UserPermissions | null> {
    return prisma.userPermissions.findUnique({ where: { userId } });
  }

  async create(userId: string, isAdmin: boolean): Promise<UserPermissions> {
    return prisma.userPermissions.create({
      data: {
        userId,
        maxScansPerDay:        isAdmin ? 9999 : 10,
        maxScansPerMonth:      isAdmin ? 9999 : 100,
        maxConcurrentScans:    isAdmin ? 10   : 2,
        maxTargetsPerScan:     isAdmin ? 10   : 1,
        maxThreads:            isAdmin ? 20   : 5,
        maxScanDuration:       isAdmin ? 3600 : 300,
        maxScanDepth:          isAdmin ? 'deep' : 'normal',
        allowedCategories:     [],
        blockedModules:        [],
        canUseOffensiveModules: isAdmin,
        canGenerateReports:    true,
        canExportData:         true,
        canCreateProfiles:     true,
        canScanInternalIPs:    isAdmin,
        canUseDeepScan:        isAdmin,
        canScheduleScans:      isAdmin,
      },
    });
  }

  async update(userId: string, data: Partial<Omit<UserPermissions, 'id' | 'userId' | 'createdAt' | 'updatedAt'>>): Promise<UserPermissions> {
    return prisma.userPermissions.upsert({
      where: { userId },
      update: data,
      create: {
        userId,
        maxScansPerDay:        data.maxScansPerDay        ?? 10,
        maxScansPerMonth:      data.maxScansPerMonth      ?? 100,
        maxConcurrentScans:    data.maxConcurrentScans    ?? 2,
        maxTargetsPerScan:     data.maxTargetsPerScan     ?? 1,
        maxThreads:            data.maxThreads            ?? 5,
        maxScanDuration:       data.maxScanDuration       ?? 300,
        maxScanDepth:          data.maxScanDepth          ?? 'normal',
        allowedCategories:     data.allowedCategories     ?? [],
        blockedModules:        data.blockedModules         ?? [],
        canUseOffensiveModules: data.canUseOffensiveModules ?? false,
        canGenerateReports:    data.canGenerateReports    ?? true,
        canExportData:         data.canExportData         ?? true,
        canCreateProfiles:     data.canCreateProfiles     ?? true,
        canScanInternalIPs:    data.canScanInternalIPs    ?? false,
        canUseDeepScan:        data.canUseDeepScan        ?? false,
        canScheduleScans:      data.canScheduleScans      ?? false,
      },
    });
  }

  async resetToDefault(userId: string, isAdmin: boolean): Promise<UserPermissions> {
    return prisma.userPermissions.upsert({
      where: { userId },
      update: {
        maxScansPerDay:        isAdmin ? 9999 : 10,
        maxScansPerMonth:      isAdmin ? 9999 : 100,
        maxConcurrentScans:    isAdmin ? 10   : 2,
        maxTargetsPerScan:     isAdmin ? 10   : 1,
        maxThreads:            isAdmin ? 20   : 5,
        maxScanDuration:       isAdmin ? 3600 : 300,
        maxScanDepth:          isAdmin ? 'deep' : 'normal',
        allowedCategories:     [],
        blockedModules:        [],
        canUseOffensiveModules: isAdmin,
        canGenerateReports:    true,
        canExportData:         true,
        canCreateProfiles:     true,
        canScanInternalIPs:    isAdmin,
        canUseDeepScan:        isAdmin,
        canScheduleScans:      isAdmin,
      },
      create: {
        userId,
        maxScansPerDay:        isAdmin ? 9999 : 10,
        maxScansPerMonth:      isAdmin ? 9999 : 100,
        maxConcurrentScans:    isAdmin ? 10   : 2,
        maxTargetsPerScan:     isAdmin ? 10   : 1,
        maxThreads:            isAdmin ? 20   : 5,
        maxScanDuration:       isAdmin ? 3600 : 300,
        maxScanDepth:          isAdmin ? 'deep' : 'normal',
        allowedCategories:     [],
        blockedModules:        [],
        canUseOffensiveModules: isAdmin,
        canGenerateReports:    true,
        canExportData:         true,
        canCreateProfiles:     true,
        canScanInternalIPs:    isAdmin,
        canUseDeepScan:        isAdmin,
        canScheduleScans:      isAdmin,
      },
    });
  }

  // Compter les scans d'aujourd'hui et du mois
  async countScansToday(userId: string): Promise<number> {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    return prisma.scan.count({ where: { userId, createdAt: { gte: startOfDay } } });
  }

  async countScansThisMonth(userId: string): Promise<number> {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);
    return prisma.scan.count({ where: { userId, createdAt: { gte: startOfMonth } } });
  }

  async countRunningScans(userId: string): Promise<number> {
    return prisma.scan.count({ where: { userId, status: { in: ['PENDING', 'RUNNING'] } } });
  }
}
