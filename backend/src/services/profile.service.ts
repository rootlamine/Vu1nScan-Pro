import { ScanProfile } from '@prisma/client';
import { ProfileRepository } from '@/repositories/profile.repository';
import { ModuleRepository }  from '@/repositories/module.repository';
import { AppError }          from '@/utils/errors';

const profileRepo = new ProfileRepository();
const moduleRepo  = new ModuleRepository();

export class ProfileService {
  async listProfiles(userId: string): Promise<ScanProfile[]> {
    return profileRepo.findByUserId(userId);
  }

  async createProfile(
    userId: string,
    data: { name: string; description?: string; modules: string[]; isDefault?: boolean },
  ): Promise<ScanProfile> {
    // Validate that module slugs exist
    const allModules = await moduleRepo.findAllActive();
    const validSlugs = new Set(allModules.map(m => m.slug));
    const invalid = data.modules.filter(s => !validSlugs.has(s));
    if (invalid.length) {
      throw new AppError(`Modules inconnus : ${invalid.join(', ')}`, 400);
    }
    return profileRepo.create(userId, data);
  }

  async updateProfile(
    id: string,
    userId: string,
    data: { name?: string; description?: string; modules?: string[]; isDefault?: boolean },
  ): Promise<ScanProfile> {
    const profile = await profileRepo.findById(id);
    if (!profile) throw new AppError('Profil introuvable', 404);
    if (profile.userId !== userId) throw new AppError('Accès refusé', 403);
    if (data.modules) {
      const allModules = await moduleRepo.findAllActive();
      const validSlugs = new Set(allModules.map(m => m.slug));
      const invalid = data.modules.filter(s => !validSlugs.has(s));
      if (invalid.length) throw new AppError(`Modules inconnus : ${invalid.join(', ')}`, 400);
    }
    return profileRepo.update(id, data);
  }

  async deleteProfile(id: string, userId: string): Promise<void> {
    const profile = await profileRepo.findById(id);
    if (!profile) throw new AppError('Profil introuvable', 404);
    if (profile.userId !== userId) throw new AppError('Accès refusé', 403);
    await profileRepo.delete(id);
  }

  async applyProfile(id: string, userId: string): Promise<{ modules: string[] }> {
    const profile = await profileRepo.findById(id);
    if (!profile) throw new AppError('Profil introuvable', 404);
    if (profile.userId !== userId) throw new AppError('Accès refusé', 403);
    return { modules: profile.modules };
  }
}
