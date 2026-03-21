import { Scan, ScanStatus } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { IScanRepository, ScanWithModules } from '@/domain/interfaces';
import { CreateScanDTO } from '@/domain/types';

export class ScanRepository implements IScanRepository {
  async create(userId: string, dto: CreateScanDTO): Promise<Scan> {
    return prisma.scan.create({
      data: {
        userId,
        targetUrl:   dto.targetUrl,
        description: dto.description,
        depth:       dto.depth       ?? 'normal',
        threads:     dto.threads     ?? 5,
      },
    });
  }

  async findById(id: string): Promise<ScanWithModules | null> {
    return prisma.scan.findUnique({
      where:   { id },
      include: { moduleResults: { include: { module: true } } },
    });
  }

  async findByUserId(
    userId: string,
    page: number,
    limit: number,
  ): Promise<{ scans: Scan[]; total: number }> {
    const skip = (page - 1) * limit;
    const [scans, total] = await Promise.all([
      prisma.scan.findMany({
        where:   { userId },
        skip,
        take:    limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.scan.count({ where: { userId } }),
    ]);
    return { scans, total };
  }

  async updateStatus(
    id: string,
    status: ScanStatus,
    timestamps?: { startedAt?: Date; completedAt?: Date },
  ): Promise<Scan> {
    return prisma.scan.update({
      where: { id },
      data:  { status, ...timestamps },
    });
  }

  async delete(id: string): Promise<void> {
    await prisma.scan.delete({ where: { id } });
  }
}
