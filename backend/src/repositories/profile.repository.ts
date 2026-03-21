import { ScanProfile } from '@prisma/client';
import { prisma } from '@/utils/prisma';

export class ProfileRepository {
  async findByUserId(userId: string): Promise<ScanProfile[]> {
    return prisma.scanProfile.findMany({
      where:   { userId },
      orderBy: [{ isDefault: 'desc' }, { createdAt: 'asc' }],
    });
  }

  async findById(id: string): Promise<ScanProfile | null> {
    return prisma.scanProfile.findUnique({ where: { id } });
  }

  async create(
    userId: string,
    data: { name: string; description?: string; modules: string[]; isDefault?: boolean },
  ): Promise<ScanProfile> {
    return prisma.scanProfile.create({
      data: { userId, ...data },
    });
  }

  async update(
    id: string,
    data: { name?: string; description?: string; modules?: string[]; isDefault?: boolean },
  ): Promise<ScanProfile> {
    return prisma.scanProfile.update({ where: { id }, data });
  }

  async delete(id: string): Promise<void> {
    await prisma.scanProfile.delete({ where: { id } });
  }
}
