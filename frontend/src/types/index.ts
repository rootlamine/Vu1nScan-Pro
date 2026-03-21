// ─── Enums ────────────────────────────────────────────────────────────────────

export type Role         = 'USER' | 'ADMIN';
export type ScanStatus   = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type Severity     = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ModuleStatus = 'PENDING' | 'RUNNING' | 'DONE' | 'ERROR';
export type ReportFormat = 'PDF' | 'JSON';

// ─── Models ───────────────────────────────────────────────────────────────────

export interface User {
  id:        string;
  username:  string;
  email:     string;
  role:      Role;
  isActive:  boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ScanModule {
  id:             string;
  name:           string;
  slug:           string;
  description:    string;
  isActive:       boolean;
  defaultEnabled: boolean;
}

export interface ScanModuleResult {
  id:            string;
  scanId:        string;
  moduleId:      string;
  module:        ScanModule;
  status:        ModuleStatus;
  executionTime?: number;
  rawOutput?:    string;
  createdAt:     string;
}

export interface Scan {
  id:           string;
  userId:       string;
  targetUrl:    string;
  description?: string;
  status:       ScanStatus;
  depth:        string;
  threads:      number;
  startedAt?:   string;
  completedAt?: string;
  createdAt:    string;
  moduleResults?: ScanModuleResult[];
}

export interface Vulnerability {
  id:             string;
  scanId:         string;
  name:           string;
  severity:       Severity;
  cvssScore?:     number;
  cveId?:         string;
  endpoint?:      string;
  parameter?:     string;
  description:    string;
  payload?:       string;
  recommendation: string;
  createdAt:      string;
}

export interface Report {
  id:          string;
  scanId:      string;
  scan:        Scan;
  format:      ReportFormat;
  filePath:    string;
  fileSize?:   number;
  generatedAt: string;
}

// ─── DTOs / réponses ─────────────────────────────────────────────────────────

export interface VulnStats {
  total:    number;
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

export interface PaginatedScans {
  scans: Scan[];
  total: number;
  page:  number;
  limit: number;
}

export interface AdminStats {
  totalUsers:    number;
  totalScans:    number;
  totalVulns:    number;
  scansByStatus: Record<ScanStatus, number>;
}
