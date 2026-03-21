import { ScanModule, ScanModuleResult, ModuleStatus } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { IModuleRepository } from '@/domain/interfaces';

export class ModuleRepository implements IModuleRepository {
  async findAllActive(): Promise<ScanModule[]> {
    return prisma.scanModule.findMany({ where: { isActive: true } });
  }

  async findByIds(ids: string[]): Promise<ScanModule[]> {
    return prisma.scanModule.findMany({ where: { id: { in: ids }, isActive: true } });
  }

  async findBySlug(slug: string): Promise<ScanModule | null> {
    return prisma.scanModule.findUnique({ where: { slug } });
  }

  async findModuleResultsByScanId(
    scanId: string,
  ): Promise<(ScanModuleResult & { module: ScanModule })[]> {
    return prisma.scanModuleResult.findMany({
      where:   { scanId },
      include: { module: true },
    });
  }

  async createModuleResults(scanId: string, moduleIds: string[]): Promise<void> {
    await prisma.scanModuleResult.createMany({
      data: moduleIds.map(moduleId => ({ scanId, moduleId })),
    });
  }

  async updateModuleResult(
    id: string,
    data: { status: ModuleStatus; executionTime?: number; rawOutput?: string },
  ): Promise<void> {
    await prisma.scanModuleResult.update({ where: { id }, data });
  }
}
