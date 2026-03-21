import {
  User, Scan, Vulnerability, ScanModule,
  ScanModuleResult, Report, ScanStatus, ModuleStatus,
} from '@prisma/client';
import { CreateUserDTO, UpdateProfileDTO, CreateScanDTO, VulnOutput } from './types';

// ─── User ────────────────────────────────────────────────────────────────────

export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  findByUsername(username: string): Promise<User | null>;
  create(dto: Omit<CreateUserDTO, 'password'> & { passwordHash: string }): Promise<User>;
  updateProfile(id: string, data: UpdateProfileDTO): Promise<User>;
  updatePassword(id: string, passwordHash: string): Promise<User>;
}

// ─── Scan ────────────────────────────────────────────────────────────────────

export type ScanWithModules = Scan & {
  moduleResults: (ScanModuleResult & { module: ScanModule })[];
};

export interface IScanRepository {
  create(userId: string, dto: CreateScanDTO): Promise<Scan>;
  findById(id: string): Promise<ScanWithModules | null>;
  findByUserId(userId: string, page: number, limit: number): Promise<{ scans: Scan[]; total: number }>;
  updateStatus(id: string, status: ScanStatus, timestamps?: { startedAt?: Date; completedAt?: Date }): Promise<Scan>;
  delete(id: string): Promise<void>;
}

// ─── Vulnerability ───────────────────────────────────────────────────────────

export interface VulnFilters {
  severity?: string;
  search?: string;
}

export interface VulnStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface IVulnRepository {
  findByScanId(scanId: string, filters?: VulnFilters): Promise<Vulnerability[]>;
  countBySeverity(scanId: string): Promise<VulnStats>;
  createMany(scanId: string, vulns: VulnOutput[]): Promise<void>;
}

// ─── Module ──────────────────────────────────────────────────────────────────

export interface IModuleRepository {
  findAllActive(): Promise<ScanModule[]>;
  findBySlug(slug: string): Promise<ScanModule | null>;
  findModuleResultsByScanId(scanId: string): Promise<(ScanModuleResult & { module: ScanModule })[]>;
  createModuleResults(scanId: string, moduleIds: string[]): Promise<void>;
  updateModuleResult(
    id: string,
    data: { status: ModuleStatus; executionTime?: number; rawOutput?: string },
  ): Promise<void>;
}

// ─── Report ──────────────────────────────────────────────────────────────────

export type ReportWithScan = Report & { scan: Scan };

export interface IReportRepository {
  create(data: { scanId: string; filePath: string; fileSize?: number }): Promise<Report>;
  findById(id: string): Promise<ReportWithScan | null>;
  findByScanId(scanId: string): Promise<Report | null>;
  findByUserId(userId: string): Promise<ReportWithScan[]>;
}
