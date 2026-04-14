import { User, ScanModule, Role } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { AdminRepository } from '@/repositories/admin.repository';
import { PermissionService } from '@/services/permission.service';
import { AppError }        from '@/utils/errors';
import { UpdateUserDTO, UpdateModuleDTO } from '@/domain/types';

const adminRepo   = new AdminRepository();
const permService = new PermissionService();

export class AdminService {
  async listUsers(): Promise<Omit<User, 'passwordHash'>[]> {
    return adminRepo.findAllUsers();
  }

  async createUser(dto: { username: string; email: string; password: string; role: Role; isActive: boolean }): Promise<Omit<User, 'passwordHash'>> {
    const passwordHash = await bcrypt.hash(dto.password, 10);
    const user = await adminRepo.createUser({ username: dto.username, email: dto.email, passwordHash, role: dto.role, isActive: dto.isActive });
    await permService.createDefaultPermissions(user.id, dto.role);
    return user;
  }

  async updateUser(id: string, dto: UpdateUserDTO): Promise<Omit<User, 'passwordHash'>> {
    const users = await adminRepo.findAllUsers();
    if (!users.find(u => u.id === id)) throw new AppError('Utilisateur introuvable', 404);
    return adminRepo.updateUser(id, dto);
  }

  async listModules(): Promise<ScanModule[]> {
    return adminRepo.findAllModules();
  }

  async updateModule(id: string, dto: UpdateModuleDTO): Promise<ScanModule> {
    const modules = await adminRepo.findAllModules();
    if (!modules.find(m => m.id === id)) throw new AppError('Module introuvable', 404);
    return adminRepo.updateModule(id, dto);
  }

  async getGlobalStats() {
    return adminRepo.getGlobalStats();
  }

  async getUserPermissions(userId: string) {
    const users = await adminRepo.findAllUsers();
    if (!users.find(u => u.id === userId)) throw new AppError('Utilisateur introuvable', 404);
    return permService.getPermissions(userId);
  }

  async updateUserPermissions(userId: string, data: Parameters<typeof permService.updatePermissions>[1]) {
    const users = await adminRepo.findAllUsers();
    const user = users.find(u => u.id === userId);
    if (!user) throw new AppError('Utilisateur introuvable', 404);
    return permService.updatePermissions(userId, data);
  }

  async resetUserPermissions(userId: string) {
    const users = await adminRepo.findAllUsers();
    const user = users.find(u => u.id === userId);
    if (!user) throw new AppError('Utilisateur introuvable', 404);
    return permService.resetToDefault(userId, user.role === 'ADMIN');
  }

  async getUserStats(userId: string) {
    return permService.getRemainingScans(userId);
  }
}
