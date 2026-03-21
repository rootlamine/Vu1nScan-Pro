import { Vulnerability, Severity } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { IVulnRepository, VulnFilters, VulnStats } from '@/domain/interfaces';
import { VulnOutput } from '@/domain/types';

export class VulnRepository implements IVulnRepository {
  async findByScanId(scanId: string, filters?: VulnFilters): Promise<Vulnerability[]> {
    return prisma.vulnerability.findMany({
      where: {
        scanId,
        ...(filters?.severity ? { severity: filters.severity as Severity } : {}),
        ...(filters?.search ? {
          OR: [
            { name:        { contains: filters.search, mode: 'insensitive' } },
            { description: { contains: filters.search, mode: 'insensitive' } },
            { endpoint:    { contains: filters.search, mode: 'insensitive' } },
          ],
        } : {}),
      },
      orderBy: [
        // Tri par sévérité : CRITICAL > HIGH > MEDIUM > LOW
        { cvssScore: 'desc' },
        { createdAt: 'asc'  },
      ],
    });
  }

  async countBySeverity(scanId: string): Promise<VulnStats> {
    const [critical, high, medium, low] = await Promise.all([
      prisma.vulnerability.count({ where: { scanId, severity: 'CRITICAL' } }),
      prisma.vulnerability.count({ where: { scanId, severity: 'HIGH'     } }),
      prisma.vulnerability.count({ where: { scanId, severity: 'MEDIUM'   } }),
      prisma.vulnerability.count({ where: { scanId, severity: 'LOW'      } }),
    ]);
    return { total: critical + high + medium + low, critical, high, medium, low };
  }

  async findByUserId(userId: string, filters?: VulnFilters & { limit?: number; page?: number }): Promise<Vulnerability[]> {
    const limit = filters?.limit ?? 50;
    const page  = filters?.page  ?? 1;
    return prisma.vulnerability.findMany({
      where: {
        scan: { userId },
        ...(filters?.severity ? { severity: filters.severity as Severity } : {}),
        ...(filters?.search ? {
          OR: [
            { name:        { contains: filters.search, mode: 'insensitive' } },
            { description: { contains: filters.search, mode: 'insensitive' } },
            { endpoint:    { contains: filters.search, mode: 'insensitive' } },
          ],
        } : {}),
      },
      include: { scan: { select: { targetUrl: true } } },
      orderBy: [{ cvssScore: 'desc' }, { createdAt: 'asc' }],
      take:  limit,
      skip:  (page - 1) * limit,
    });
  }

  async countByUserIdAndSeverity(userId: string): Promise<VulnStats> {
    const [critical, high, medium, low] = await Promise.all([
      prisma.vulnerability.count({ where: { scan: { userId }, severity: 'CRITICAL' } }),
      prisma.vulnerability.count({ where: { scan: { userId }, severity: 'HIGH'     } }),
      prisma.vulnerability.count({ where: { scan: { userId }, severity: 'MEDIUM'   } }),
      prisma.vulnerability.count({ where: { scan: { userId }, severity: 'LOW'      } }),
    ]);
    return { total: critical + high + medium + low, critical, high, medium, low };
  }

  async createMany(scanId: string, vulns: VulnOutput[]): Promise<void> {
    if (!vulns.length) return;
    await prisma.vulnerability.createMany({
      data: vulns.map(v => ({
        scanId,
        name:           v.name,
        severity:       v.severity as Severity,
        cvssScore:      v.cvss_score,
        cvssVector:     v.cvss_vector,
        cveId:          v.cve_id,
        cweId:          v.cwe_id,
        endpoint:       v.endpoint,
        parameter:      v.parameter,
        description:    v.description,
        payload:        v.payload,
        evidence:       v.evidence,
        impact:         v.impact,
        recommendation: v.recommendation,
        references:     v.references ?? [],
      })),
    });
  }

  async findById(id: string): Promise<Vulnerability | null> {
    return prisma.vulnerability.findUnique({ where: { id } });
  }

  async update(id: string, data: {
    isResolved?: boolean;
    isFalsePositive?: boolean;
    notes?: string;
    resolvedAt?: Date | null;
  }): Promise<Vulnerability> {
    return prisma.vulnerability.update({ where: { id }, data });
  }
}
