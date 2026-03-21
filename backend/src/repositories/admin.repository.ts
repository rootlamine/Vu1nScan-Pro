import { User, ScanModule, Role } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { UpdateUserDTO, UpdateModuleDTO } from '@/domain/types';

export class AdminRepository {
  async findAllUsers(): Promise<Omit<User, 'passwordHash'>[]> {
    const users = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });
    return users.map(({ passwordHash: _, ...u }) => u);
  }

  async createUser(data: { username: string; email: string; passwordHash: string; role: Role; isActive: boolean }): Promise<Omit<User, 'passwordHash'>> {
    const user = await prisma.user.create({ data });
    const { passwordHash: _, ...safe } = user;
    return safe;
  }

  async updateUser(id: string, data: UpdateUserDTO): Promise<Omit<User, 'passwordHash'>> {
    const user = await prisma.user.update({ where: { id }, data });
    const { passwordHash: _, ...safe } = user;
    return safe;
  }

  async findAllModules(): Promise<ScanModule[]> {
    return prisma.scanModule.findMany({ orderBy: { name: 'asc' } });
  }

  async updateModule(id: string, data: UpdateModuleDTO): Promise<ScanModule> {
    return prisma.scanModule.update({ where: { id }, data });
  }

  async getGlobalStats(): Promise<{
    totalUsers:    number;
    totalScans:    number;
    totalVulns:    number;
    scansByStatus: Record<string, number>;
  }> {
    const [totalUsers, totalScans, totalVulns, statusGroups] = await Promise.all([
      prisma.user.count(),
      prisma.scan.count(),
      prisma.vulnerability.count(),
      prisma.scan.groupBy({ by: ['status'], _count: { _all: true } }),
    ]);
    const scansByStatus: Record<string, number> = {};
    for (const g of statusGroups) scansByStatus[g.status] = g._count._all;
    return { totalUsers, totalScans, totalVulns, scansByStatus };
  }
}
