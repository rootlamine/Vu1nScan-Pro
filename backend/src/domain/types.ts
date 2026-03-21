import { Role } from '@prisma/client';

// ─── Auth ────────────────────────────────────────────────────────────────────

export interface CreateUserDTO {
  username: string;
  email: string;
  password: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export interface UpdateProfileDTO {
  username?: string;
  email?: string;
}

export interface ChangePasswordDTO {
  currentPassword: string;
  newPassword: string;
}

export interface JwtPayload {
  userId: string;
  email: string;
  role: Role;
}

// ─── Scans ───────────────────────────────────────────────────────────────────

export interface CreateScanDTO {
  targetUrl: string;
  description?: string;
  depth?: string;
  threads?: number;
  moduleIds?: string[];
}

export interface ScanJobData {
  scanId: string;
  targetUrl: string;
  depth: string;
  moduleSlugs: string[];
}

// ─── Scanner output ──────────────────────────────────────────────────────────

export interface VulnOutput {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  endpoint?: string;
  parameter?: string;
  description: string;
  payload?: string;
  evidence?: string;
  impact?: string;
  recommendation: string;
  references?: string[];
}

export interface UpdateVulnDTO {
  isResolved?: boolean;
  isFalsePositive?: boolean;
  notes?: string;
}

export interface ModuleOutput {
  module: string;
  status: 'success' | 'error';
  duration_ms: number;
  error: string | null;
  vulnerabilities: VulnOutput[];
}

// ─── Admin ───────────────────────────────────────────────────────────────────

export interface UpdateUserDTO {
  role?: Role;
  isActive?: boolean;
}

export interface UpdateModuleDTO {
  isActive?: boolean;
  defaultEnabled?: boolean;
}
