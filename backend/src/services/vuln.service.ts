import { Vulnerability } from '@prisma/client';
import { VulnRepository } from '@/repositories/vuln.repository';
import { ScanRepository } from '@/repositories/scan.repository';
import { AppError }       from '@/utils/errors';
import { VulnFilters, VulnStats } from '@/domain/interfaces';

const vulnRepo = new VulnRepository();
const scanRepo = new ScanRepository();

export class VulnService {
  async listVulnerabilities(
    scanId: string,
    userId: string,
    filters?: VulnFilters,
  ): Promise<Vulnerability[]> {
    const scan = await scanRepo.findById(scanId);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);
    return vulnRepo.findByScanId(scanId, filters);
  }

  async getStats(scanId: string, userId: string): Promise<VulnStats> {
    const scan = await scanRepo.findById(scanId);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);
    return vulnRepo.countBySeverity(scanId);
  }

  async listAll(userId: string, filters?: VulnFilters & { limit?: number; page?: number }): Promise<Vulnerability[]> {
    return vulnRepo.findByUserId(userId, filters);
  }

  async getGlobalStats(userId: string): Promise<VulnStats> {
    return vulnRepo.countByUserIdAndSeverity(userId);
  }
}
