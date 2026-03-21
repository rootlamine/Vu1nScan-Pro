import { Scan } from '@prisma/client';
import { ScanRepository }   from '@/repositories/scan.repository';
import { ModuleRepository } from '@/repositories/module.repository';
import { addScanJob }       from '@/jobs/scan-queue';
import { AppError }         from '@/utils/errors';
import { CreateScanDTO, ScanJobData } from '@/domain/types';
import { ScanWithModules }  from '@/domain/interfaces';

const scanRepo   = new ScanRepository();
const moduleRepo = new ModuleRepository();

export class ScanService {
  async createScan(userId: string, dto: CreateScanDTO): Promise<ScanWithModules> {
    // 1. Créer le scan en base
    const scan = await scanRepo.create(userId, dto);

    // 2. Récupérer les modules actifs par défaut
    const modules = await moduleRepo.findAllActive();
    const activeModules = modules.filter(m => m.defaultEnabled);

    if (!activeModules.length) {
      throw new AppError('Aucun module de scan disponible', 503);
    }

    // 3. Créer les ScanModuleResults (PENDING)
    await moduleRepo.createModuleResults(scan.id, activeModules.map(m => m.id));

    // 4. Ajouter le job BullMQ
    const jobData: ScanJobData = {
      scanId:      scan.id,
      targetUrl:   dto.targetUrl,
      depth:       dto.depth ?? 'normal',
      moduleSlugs: activeModules.map(m => m.slug),
    };
    await addScanJob(jobData);

    // 5. Retourner le scan avec ses moduleResults
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
