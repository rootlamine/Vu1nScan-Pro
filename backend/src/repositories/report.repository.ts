import { Report } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { IReportRepository, ReportWithScan } from '@/domain/interfaces';

export class ReportRepository implements IReportRepository {
  async create(data: { scanId: string; filePath: string; fileSize?: number }): Promise<Report> {
    return prisma.report.create({ data });
  }

  async findById(id: string): Promise<ReportWithScan | null> {
    return prisma.report.findUnique({
      where:   { id },
      include: { scan: true },
    });
  }

  async findByScanId(scanId: string): Promise<Report | null> {
    return prisma.report.findUnique({ where: { scanId } });
  }

  async findByUserId(userId: string): Promise<ReportWithScan[]> {
    return prisma.report.findMany({
      where:   { scan: { userId } },
      include: { scan: true },
      orderBy: { generatedAt: 'desc' },
    });
  }
}
