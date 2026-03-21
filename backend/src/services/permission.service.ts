import { UserPermissions, Role } from '@prisma/client';
import { PermissionRepository } from '@/repositories/permission.repository';
import { AppError } from '@/utils/errors';
import { CreateScanDTO } from '@/domain/types';

const permRepo = new PermissionRepository();

const OFFENSIVE_CATEGORIES = ['WEB_OFFENSIVE', 'API_OFFENSIVE', 'NETWORK_OFFENSIVE'];
const INTERNAL_IP_RE = /^(http:\/\/)?(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|localhost)/i;

export class PermissionService {
  async createDefaultPermissions(userId: string, role: Role): Promise<UserPermissions> {
    return permRepo.create(userId, role === 'ADMIN');
  }

  async getPermissions(userId: string): Promise<UserPermissions> {
    let perms = await permRepo.findByUserId(userId);
    if (!perms) {
      perms = await permRepo.create(userId, false);
    }
    return perms;
  }

  async updatePermissions(
    userId: string,
    data: Partial<Omit<UserPermissions, 'id' | 'userId' | 'createdAt' | 'updatedAt'>>,
  ): Promise<UserPermissions> {
    return permRepo.update(userId, data);
  }

  async resetToDefault(userId: string, isAdmin: boolean): Promise<UserPermissions> {
    return permRepo.resetToDefault(userId, isAdmin);
  }

  async getRemainingScans(userId: string): Promise<{
    todayUsed: number;
    todayMax: number;
    todayRemaining: number;
    monthUsed: number;
    monthMax: number;
    monthRemaining: number;
    runningScans: number;
    maxConcurrent: number;
  }> {
    const [perms, todayUsed, monthUsed, runningScans] = await Promise.all([
      this.getPermissions(userId),
      permRepo.countScansToday(userId),
      permRepo.countScansThisMonth(userId),
      permRepo.countRunningScans(userId),
    ]);

    return {
      todayUsed,
      todayMax:       perms.maxScansPerDay,
      todayRemaining: Math.max(0, perms.maxScansPerDay - todayUsed),
      monthUsed,
      monthMax:       perms.maxScansPerMonth,
      monthRemaining: Math.max(0, perms.maxScansPerMonth - monthUsed),
      runningScans,
      maxConcurrent:  perms.maxConcurrentScans,
    };
  }

  async checkScanPermissions(
    userId: string,
    role: Role,
    dto: CreateScanDTO,
    moduleCategories: string[],
  ): Promise<void> {
    // ADMIN : aucune restriction
    if (role === 'ADMIN') return;

    const [perms, todayCount, monthCount, runningCount] = await Promise.all([
      this.getPermissions(userId),
      permRepo.countScansToday(userId),
      permRepo.countScansThisMonth(userId),
      permRepo.countRunningScans(userId),
    ]);

    if (todayCount >= perms.maxScansPerDay)
      throw new AppError(`Limite journalière atteinte (${perms.maxScansPerDay} scans/jour)`, 429);

    if (monthCount >= perms.maxScansPerMonth)
      throw new AppError(`Limite mensuelle atteinte (${perms.maxScansPerMonth} scans/mois)`, 429);

    if (runningCount >= perms.maxConcurrentScans)
      throw new AppError(`Trop de scans simultanés (max ${perms.maxConcurrentScans})`, 429);

    if (!perms.canScanInternalIPs && INTERNAL_IP_RE.test(dto.targetUrl))
      throw new AppError('Vous n\'êtes pas autorisé à scanner des IPs internes', 403);

    if (!perms.canUseDeepScan && dto.depth === 'deep')
      throw new AppError('Vous n\'êtes pas autorisé à utiliser le mode deep scan', 403);

    if (dto.threads && dto.threads > perms.maxThreads)
      throw new AppError(`Nombre de threads limité à ${perms.maxThreads}`, 400);

    if (!perms.canUseOffensiveModules && moduleCategories.some(c => OFFENSIVE_CATEGORIES.includes(c)))
      throw new AppError('Vous n\'êtes pas autorisé à utiliser les modules offensifs', 403);

    if (perms.blockedModules.length > 0) {
      // blockedModules contains slugs — checked in scan.service
    }
  }
}
