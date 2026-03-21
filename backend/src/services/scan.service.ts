import { Scan, Role } from '@prisma/client';
import { ScanRepository }    from '@/repositories/scan.repository';
import { ModuleRepository }  from '@/repositories/module.repository';
import { PermissionService } from '@/services/permission.service';
import { addScanJob }        from '@/jobs/scan-queue';
import { AppError }          from '@/utils/errors';
import { CreateScanDTO, ScanJobData } from '@/domain/types';
import { ScanWithModules }   from '@/domain/interfaces';

const scanRepo   = new ScanRepository();
const moduleRepo = new ModuleRepository();
const permSvc    = new PermissionService();

export class ScanService {
  async createScan(userId: string, role: Role, dto: CreateScanDTO): Promise<ScanWithModules> {
    // 1. Récupérer les modules candidats (avant création scan, pour vérif permissions)
    let activeModules;
    if (dto.moduleIds && dto.moduleIds.length > 0) {
      activeModules = await moduleRepo.findByIds(dto.moduleIds);
    } else {
      const modules = await moduleRepo.findAllActive();
      activeModules = modules.filter(m => m.defaultEnabled);
    }

    if (!activeModules.length) {
      throw new AppError('Aucun module de scan disponible', 503);
    }

    // 2. Vérifier les permissions
    const moduleCategories = activeModules.map(m => m.category as string);
    await permSvc.checkScanPermissions(userId, role, dto, moduleCategories);

    // 3. Filtrer les modules bloqués pour les non-admins
    if (role !== 'ADMIN') {
      const perms = await permSvc.getPermissions(userId);
      if (perms.blockedModules.length > 0) {
        activeModules = activeModules.filter(m => !perms.blockedModules.includes(m.slug));
      }
      if (!activeModules.length) {
        throw new AppError('Tous les modules sélectionnés sont bloqués pour votre compte', 403);
      }
    }

    // 4. Créer le scan en base
    const scan = await scanRepo.create(userId, dto);

    // 5. Créer les ScanModuleResults (PENDING)
    await moduleRepo.createModuleResults(scan.id, activeModules.map(m => m.id));

    // 6. Ajouter le job BullMQ
    const jobData: ScanJobData = {
      scanId:      scan.id,
      targetUrl:   dto.targetUrl,
      depth:       dto.depth ?? 'normal',
      moduleSlugs: activeModules.map(m => m.slug),
    };
    await addScanJob(jobData);

    // 7. Retourner le scan avec ses moduleResults
    const fullScan = await scanRepo.findById(scan.id);
    return fullScan!;
  }

  async listScans(
    userId: string,
    page = 1,
    limit = 10,
  ): Promise<{ scans: Scan[]; total: number; page: number; limit: number }> {
    const { scans, total } = await scanRepo.findByUserId(userId, page, limit);
    return { scans, total, page, limit };
  }

  async getScan(id: string, userId: string): Promise<ScanWithModules> {
    const scan = await scanRepo.findById(id);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);
    return scan;
  }

  async deleteScan(id: string, userId: string): Promise<void> {
    const scan = await scanRepo.findById(id);
    if (!scan) throw new AppError('Scan introuvable', 404);
    if (scan.userId !== userId) throw new AppError('Accès refusé', 403);
    await scanRepo.delete(id);
  }
}
