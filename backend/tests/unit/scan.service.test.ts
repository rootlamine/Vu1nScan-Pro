import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScanService } from '@/services/scan.service';

const mockScanRepo = vi.hoisted(() => ({
  create:       vi.fn(),
  findById:     vi.fn(),
  findByUserId: vi.fn(),
  updateStatus: vi.fn(),
  delete:       vi.fn(),
}));

const mockModRepo = vi.hoisted(() => ({
  findAllActive:             vi.fn(),
  createModuleResults:       vi.fn(),
  findModuleResultsByScanId: vi.fn(),
  updateModuleResult:        vi.fn(),
}));

vi.mock('@/repositories/scan.repository', () => ({
  ScanRepository: vi.fn().mockImplementation(() => mockScanRepo),
}));

vi.mock('@/repositories/module.repository', () => ({
  ModuleRepository: vi.fn().mockImplementation(() => mockModRepo),
}));

vi.mock('@/jobs/scan-queue', () => ({
  addScanJob: vi.fn().mockResolvedValue(undefined),
}));

describe('ScanService', () => {
  let service: ScanService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new ScanService();
  });

  describe('createScan', () => {
    it('crée un scan et enqueue le job', async () => {
      const fakeScan = {
        id: 'scan-1', userId: 'user-1', targetUrl: 'http://example.com',
        status: 'PENDING', depth: 'normal', threads: 5, createdAt: new Date(),
      };
      const fakeModules = [
        { id: 'mod-1', slug: 'http_headers', isActive: true, defaultEnabled: true },
      ];

      mockScanRepo.create.mockResolvedValue(fakeScan);
      mockModRepo.findAllActive.mockResolvedValue(fakeModules);
      mockModRepo.createModuleResults.mockResolvedValue(undefined);
      mockScanRepo.findById.mockResolvedValue({ ...fakeScan, moduleResults: [] });

      const result = await service.createScan('user-1', {
        targetUrl: 'http://example.com',
        depth:     'normal',
      });

      expect(result.id).toBe('scan-1');
      const { addScanJob } = await import('@/jobs/scan-queue');
      expect(addScanJob).toHaveBeenCalledOnce();
    });

    it('lance AppError 503 si aucun module actif', async () => {
      mockScanRepo.create.mockResolvedValue({ id: 'scan-1' });
      mockModRepo.findAllActive.mockResolvedValue([]);

      await expect(
        service.createScan('user-1', { targetUrl: 'http://example.com' }),
      ).rejects.toMatchObject({ statusCode: 503 });
    });
  });

  describe('getScan', () => {
    it('lance AppError 403 si ownership incorrect', async () => {
      mockScanRepo.findById.mockResolvedValue({ id: 'scan-1', userId: 'autre-user', moduleResults: [] });

      await expect(
        service.getScan('scan-1', 'mon-user'),
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('lance AppError 404 si scan introuvable', async () => {
      mockScanRepo.findById.mockResolvedValue(null);

      await expect(
        service.getScan('inexistant', 'user-1'),
      ).rejects.toMatchObject({ statusCode: 404 });
    });
  });
});
