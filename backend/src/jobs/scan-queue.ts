import { Queue } from 'bullmq';
import { bullmqConnection } from '@/utils/redis';
import { ScanJobData } from '@/domain/types';

export const scanQueue = new Queue<ScanJobData, void, string>('scan-jobs', {
  connection:        bullmqConnection,
  defaultJobOptions: {
    attempts:         2,
    backoff:          { type: 'fixed', delay: 5000 },
    removeOnComplete: 100,
    removeOnFail:     100,
  },
});

export async function addScanJob(data: ScanJobData): Promise<void> {
  await scanQueue.add('process-scan', data, { jobId: data.scanId });
}
