import { Worker, Job } from 'bullmq';
import { bullmqConnection } from '@/utils/redis';
import { runAll } from '@/scanner/scan-engine';
import { ScanRepository }   from '@/repositories/scan.repository';
import { ModuleRepository } from '@/repositories/module.repository';
import { VulnRepository }   from '@/repositories/vuln.repository';
import { ScanJobData }      from '@/domain/types';

const scanRepo   = new ScanRepository();
const moduleRepo = new ModuleRepository();
const vulnRepo   = new VulnRepository();

async function processJob(job: Job<ScanJobData>): Promise<void> {
  const { scanId, targetUrl, depth, moduleSlugs } = job.data;

  console.log(`[Worker] Démarrage scan ${scanId} sur ${targetUrl}`);

  try {
    // 1. Scan → RUNNING
    await scanRepo.updateStatus(scanId, 'RUNNING', { startedAt: new Date() });

    // 2. Récupérer les ScanModuleResults pour ce scan
    const moduleResults = await moduleRepo.findModuleResultsByScanId(scanId);
    const resultMap = new Map(moduleResults.map(r => [r.module.slug, r]));

    // Marquer tous les modules comme RUNNING
    await Promise.all(
      moduleResults.map(r => moduleRepo.updateModuleResult(r.id, { status: 'RUNNING' })),
    );

    // 3. Lancer tous les modules Python en parallèle
    const settled = await runAll(moduleSlugs, targetUrl, depth);

    // 4. Traiter chaque résultat
    for (const settledResult of settled) {
      if (settledResult.status === 'rejected') continue;

      const output  = settledResult.value;
      const dbResult = resultMap.get(output.module);
      if (!dbResult) continue;

      const moduleStatus = output.status === 'success' ? 'DONE' : 'ERROR';
      await moduleRepo.updateModuleResult(dbResult.id, {
        status:        moduleStatus,
        executionTime: output.duration_ms,
        rawOutput:     JSON.stringify(output).slice(0, 50000), // limite taille
      });

      // Persister les vulnérabilités trouvées
      if (output.vulnerabilities?.length) {
        await vulnRepo.createMany(scanId, output.vulnerabilities);
      }
    }

    // 5. Scan → COMPLETED
    await scanRepo.updateStatus(scanId, 'COMPLETED', { completedAt: new Date() });
    console.log(`[Worker] Scan ${scanId} terminé avec succès`);

  } catch (err) {
    console.error(`[Worker] Scan ${scanId} échoué :`, (err as Error).message);
    await scanRepo.updateStatus(scanId, 'FAILED', { completedAt: new Date() });
    throw err; // BullMQ marquera le job comme failed
  }
}

// Le worker ne démarre pas en mode test
if (process.env.NODE_ENV !== 'test') {
  const worker = new Worker<ScanJobData>('scan-jobs', processJob, {
    connection:  bullmqConnection,
    concurrency: 3,
  });

  worker.on('completed', (job) => console.log(`[Worker] Job ${job.id} terminé`));
  worker.on('failed',    (job, err) => console.error(`[Worker] Job ${job?.id} échoué :`, err.message));

  console.log('[Worker] BullMQ scan-worker démarré (concurrency: 3)');
}
